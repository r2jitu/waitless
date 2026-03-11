// kernel/aarch64/exceptions.cc — ARM64 exception handling + GIC init
//
// Installs the vector table (defined in boot.S) and initialises the ARM GIC
// so we can receive IRQs.  Supports both GICv2 (QEMU virt) and GICv3 (Apple
// VZ.framework).
//
// GIC addresses are discovered from the DTB via fdt::info().
//   • gic_version == 2: GICv2 — memory-mapped GICD + GICC
//   • gic_version == 3: GICv3 — memory-mapped GICD + GICR, system register
//                        CPU interface (ICC_*_EL1)
//   • gic_version == 0: no GIC found — polling mode only

#include "kernel/aarch64/exceptions.h"
#include "kernel/fdt.h"
#include "kernel/panic.h"
#include "kernel/serial.h"

namespace exceptions {

// ---- GIC register bases (filled from FDT at init time) --------------------

static uint64_t GICD_BASE = 0;
static uint64_t GICC_BASE = 0;  // GICv2 only
static uint64_t GICR_BASE = 0;  // GICv3 only
static uint8_t gic_version_ = 0;

// ---- Distributor registers (shared between GICv2 and GICv3) ---------------

static constexpr uint32_t GICD_CTLR = 0x000;
static constexpr uint32_t GICD_TYPER = 0x004;
static constexpr uint32_t GICD_IGROUPR0 = 0x080;
static constexpr uint32_t GICD_ISENABLER0 = 0x100;
static constexpr uint32_t GICD_ICENABLER0 = 0x180;
static constexpr uint32_t GICD_ICPENDR0 = 0x280;
static constexpr uint32_t GICD_IPRIORITYR0 = 0x400;
static constexpr uint32_t GICD_ITARGETSR0 = 0x800; // GICv2 only

// GICv3 distributor CTLR bits
static constexpr uint32_t GICD_CTLR_ARE_NS = (1 << 4);
static constexpr uint32_t GICD_CTLR_ENABLE_GRP1_NS = (1 << 1);

// GICv3: SPI affinity routing — GICD_IROUTER<n> at offset 0x6000 + 8*n
static constexpr uint32_t GICD_IROUTER_BASE = 0x6100; // first SPI = INTID 32

// ---- GICv2 CPU interface registers ----------------------------------------

static constexpr uint32_t GICC_CTLR = 0x000;
static constexpr uint32_t GICC_PMR = 0x004;
static constexpr uint32_t GICC_IAR = 0x00C;
static constexpr uint32_t GICC_EOIR = 0x010;

// ---- GICv3 redistributor registers ---------------------------------------

static constexpr uint32_t GICR_WAKER = 0x014;

// ---- MMIO helpers ---------------------------------------------------------

static inline volatile uint32_t *gicd(uint32_t off) {
  return reinterpret_cast<volatile uint32_t *>(GICD_BASE + off);
}
static inline volatile uint32_t *gicc(uint32_t off) {
  return reinterpret_cast<volatile uint32_t *>(GICC_BASE + off);
}
static inline volatile uint32_t *gicr(uint32_t off) {
  return reinterpret_cast<volatile uint32_t *>(GICR_BASE + off);
}

// ---- IRQ handler table ----------------------------------------------------

static constexpr int MAX_IRQS = 256;
static void (*irq_handlers[MAX_IRQS])(uint32_t irq);

// ---- Exception handler (called from vector stubs in boot.S) ---------------

extern "C" void exception_handler(uint32_t kind, Frame *frame) {
  if (kind == 1) {
    // IRQ
    if (gic_version_ == 3) {
      // GICv3: acknowledge via system register
      uint64_t iar;
      asm volatile("mrs %0, ICC_IAR1_EL1" : "=r"(iar));
      uint32_t intid = (uint32_t)(iar & 0xFFFFFF);
      if (intid < 1020) {
        if (intid < MAX_IRQS && irq_handlers[intid])
          irq_handlers[intid](intid);
        asm volatile("msr ICC_EOIR1_EL1, %0" ::"r"(iar));
      }
      // intid 1023 = spurious
    } else if (gic_version_ == 2) {
      // GICv2: acknowledge via memory-mapped GICC
      uint32_t iar = *gicc(GICC_IAR);
      uint32_t irq = iar & 0x3FF;
      if (irq < 1020) {
        if (irq < MAX_IRQS && irq_handlers[irq])
          irq_handlers[irq](irq);
        *gicc(GICC_EOIR) = iar;
      }
    }
    // gic_version_ == 0: no GIC, WFI woke us, nothing to ack
  } else {
    const char *kind_str = "unknown";
    switch (kind) {
    case 0:
      kind_str = "synchronous";
      break;
    case 1:
      kind_str = "IRQ";
      break;
    case 2:
      kind_str = "FIQ";
      break;
    case 3:
      kind_str = "SError";
      break;
    }
    serial::printf("\n*** ARM64 EXCEPTION: kind=%s\n", kind_str);
    serial::printf("    ESR_EL1  = 0x%lx\n", frame->esr);
    serial::printf("    FAR_EL1  = 0x%lx\n", frame->far);
    serial::printf("    ELR_EL1  = 0x%lx  (PC at fault)\n", frame->pc);
    serial::printf("    SPSR_EL1 = 0x%lx\n", frame->pstate);
    serial::printf("    x0  = 0x%lx  x1  = 0x%lx\n", frame->x[0], frame->x[1]);
    kernel_panic("Unhandled ARM64 exception");
  }
}

// ---- GICv2 initialisation -------------------------------------------------

static void init_gicv2() {
  GICC_BASE = GICD_BASE + 0x10000;

  // Disable distributor while configuring
  *gicd(GICD_CTLR) = 0;
  asm volatile("dsb sy" ::: "memory");

  uint32_t typer = *gicd(GICD_TYPER);
  uint32_t it_lines = (typer & 0x1F) + 1;
  uint32_t num_irqs = it_lines * 32;

  for (uint32_t i = 0; i < num_irqs / 32; i++) {
    *gicd(GICD_IGROUPR0 + i * 4) = 0x00000000;   // Group 0
    *gicd(GICD_ICENABLER0 + i * 4) = 0xFFFFFFFF; // All disabled
    *gicd(GICD_ICPENDR0 + i * 4) = 0xFFFFFFFF;   // Clear pending
  }
  for (uint32_t i = 0; i < num_irqs / 4; i++) {
    *gicd(GICD_IPRIORITYR0 + i * 4) = 0xA0A0A0A0;
    *gicd(GICD_ITARGETSR0 + i * 4) = 0x01010101;
  }

  *gicd(GICD_CTLR) = 1;
  *gicc(GICC_PMR) = 0xFF;
  *gicc(GICC_CTLR) = 1;
  asm volatile("dsb sy\n\tisb" ::: "memory");

  serial::printf("       GICv2 init: %u IRQ lines\n", num_irqs);
}

// ---- GICv3 initialisation -------------------------------------------------

static void init_gicv3() {
  uint32_t typer = *gicd(GICD_TYPER);
  uint32_t it_lines = (typer & 0x1F) + 1;
  uint32_t num_irqs = it_lines * 32;

  // Check if the distributor is already configured (VZ.framework pre-inits
  // its vGIC).  If so, skip the heavy reconfiguration — resetting GICD_CTLR
  // and bulk-writing IROUTER/IGROUPR can break VZ's internal vGIC state.
  uint32_t ctlr = *gicd(GICD_CTLR);
  bool already_configured = (ctlr & GICD_CTLR_ENABLE_GRP1_NS) != 0;

  if (!already_configured) {
    // ---- Redistributor: wake up CPU 0's frame ----
    if (GICR_BASE != 0) {
      uint32_t waker = *gicr(GICR_WAKER);
      waker &= ~(1U << 1); // Clear ProcessorSleep
      *gicr(GICR_WAKER) = waker;
      for (int i = 0; i < 1000000; i++) {
        if (!(*gicr(GICR_WAKER) & (1U << 2)))
          break;
        asm volatile("nop");
      }
    }

    // ---- Full distributor init (QEMU, bare metal) ----
    *gicd(GICD_CTLR) = 0;
    asm volatile("dsb sy" ::: "memory");

    for (uint32_t i = 1; i < num_irqs / 32; i++) {
      *gicd(GICD_IGROUPR0 + i * 4) = 0xFFFFFFFF;   // Group 1 NS
      *gicd(GICD_ICENABLER0 + i * 4) = 0xFFFFFFFF;  // Disabled
      *gicd(GICD_ICPENDR0 + i * 4) = 0xFFFFFFFF;    // Clear pending
    }
    for (uint32_t i = 8; i < num_irqs / 4; i++) {
      *gicd(GICD_IPRIORITYR0 + i * 4) = 0xA0A0A0A0;
    }

    // Route all SPIs to affinity 0.0.0.0 (CPU 0)
    for (uint32_t intid = 32; intid < num_irqs; intid++) {
      volatile uint64_t *router = reinterpret_cast<volatile uint64_t *>(
          GICD_BASE + GICD_IROUTER_BASE + (intid - 32) * 8);
      *router = 0;
    }

    *gicd(GICD_CTLR) = GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_GRP1_NS;
    asm volatile("dsb sy" ::: "memory");
    serial::printf("       GICv3 init: %u IRQ lines (full)\n", num_irqs);
  } else {
    serial::printf("       GICv3 init: %u IRQ lines (vGIC pre-configured)\n",
                   num_irqs);
  }

  // ---- CPU interface (system registers) — always needed ----
  uint64_t sre;
  asm volatile("mrs %0, ICC_SRE_EL1" : "=r"(sre));
  sre |= 1;
  asm volatile("msr ICC_SRE_EL1, %0" ::"r"(sre));
  asm volatile("isb");

  asm volatile("msr ICC_PMR_EL1, %0" ::"r"((uint64_t)0xFF));
  asm volatile("msr ICC_BPR1_EL1, %0" ::"r"((uint64_t)0));
  asm volatile("msr ICC_IGRPEN1_EL1, %0" ::"r"((uint64_t)1));
  asm volatile("isb");
}

// ---- Public interface -----------------------------------------------------

void init() {
  const fdt::Info &fdt = fdt::info();
  GICD_BASE = fdt.gic_dist_base;
  GICR_BASE = fdt.gic_redist_base;
  gic_version_ = fdt.gic_version;

  if (gic_version_ == 3) {
    init_gicv3();
  } else if (gic_version_ == 2) {
    init_gicv2();
  } else {
    serial::printf("       GIC init skipped (no GIC in DTB)\n");
  }
}

// GICv3 redistributor SGI frame offset (PPIs/SGIs live here, not in GICD)
static constexpr uint32_t GICR_SGI_BASE = 0x10000;

void register_irq(uint32_t irq, void (*handler)(uint32_t)) {
  if (irq >= MAX_IRQS)
    return;
  irq_handlers[irq] = handler;

  if (GICD_BASE == 0)
    return;

  uint32_t reg_idx = irq / 32;
  uint32_t bit = 1U << (irq % 32);

  if (irq < 32 && gic_version_ == 3 && GICR_BASE != 0) {
    // GICv3: PPIs/SGIs (INTID 0-31) are in the GICR SGI frame.
    volatile uint32_t *gicr_isenabler = reinterpret_cast<volatile uint32_t *>(
        GICR_BASE + GICR_SGI_BASE + GICD_ISENABLER0);
    *gicr_isenabler = bit;
  } else {
    // SPIs (INTID >= 32) or GICv2: enable in the distributor.
    *gicd(GICD_ISENABLER0 + reg_idx * 4) = bit;
  }
}

// Enable the ARM virtual timer PPI (INTID 27) for timer-based WFI wakeup.
// The timer handler is a no-op — we just need WFI to wake up periodically.
static void timer_irq(uint32_t /*irq*/) {
  // Mask timer output to prevent retriggering before the next idle().
  asm volatile("msr CNTV_CTL_EL0, %0" ::"r"((uint64_t)2)); // ENABLE=0,IMASK=1
}

void enable_timer_wakeup() {
  register_irq(27, timer_irq);
}

} // namespace exceptions
