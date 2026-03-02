// kernel/aarch64/exceptions.cc — ARM64 exception handling + GIC init
//
// Installs the vector table (defined in boot.S) and initialises the
// ARM GIC v2 distributor / CPU interface so we can receive IRQs.
//
// GICv2 addresses on QEMU "virt" machine:
//   Distributor:    0x08000000
//   CPU interface:  0x08010000

#include "kernel/aarch64/exceptions.h"
#include "kernel/serial.h"
#include "kernel/panic.h"

namespace exceptions {

// ---- GIC v2 register bases ------------------------------------------------

static constexpr uint64_t GICD_BASE = 0x08000000UL;
static constexpr uint64_t GICC_BASE = 0x08010000UL;

// Distributor registers (offsets from GICD_BASE)
static constexpr uint32_t GICD_CTLR     = 0x000; // Distributor control
static constexpr uint32_t GICD_TYPER    = 0x004; // Interrupt controller type
static constexpr uint32_t GICD_IGROUPR0 = 0x080; // Interrupt group (bank 0)
static constexpr uint32_t GICD_ISENABLER0 = 0x100; // Interrupt set-enable
static constexpr uint32_t GICD_ICENABLER0 = 0x180; // Interrupt clear-enable
static constexpr uint32_t GICD_ICPENDR0   = 0x280; // Clear pending
static constexpr uint32_t GICD_IPRIORITYR0 = 0x400; // Priority registers
static constexpr uint32_t GICD_ITARGETSR0  = 0x800; // Target CPU registers
static constexpr uint32_t GICD_ICFGR0      = 0xC00; // Configuration

// CPU interface registers (offsets from GICC_BASE)
static constexpr uint32_t GICC_CTLR  = 0x000; // CPU interface control
static constexpr uint32_t GICC_PMR   = 0x004; // Interrupt priority mask
static constexpr uint32_t GICC_IAR   = 0x00C; // Interrupt acknowledge register
static constexpr uint32_t GICC_EOIR  = 0x010; // End of interrupt register

static inline volatile uint32_t* gicd(uint32_t off) {
    return reinterpret_cast<volatile uint32_t*>(GICD_BASE + off);
}
static inline volatile uint32_t* gicc(uint32_t off) {
    return reinterpret_cast<volatile uint32_t*>(GICC_BASE + off);
}

// ---- IRQ handler table ----------------------------------------------------

static constexpr int MAX_IRQS = 256;
static void (*irq_handlers[MAX_IRQS])(uint32_t irq);

// ---- Exception handler (called from vector stubs in boot.S) ---------------

extern "C" void exception_handler(uint32_t kind, Frame* frame) {
    if (kind == 2) {
        // IRQ
        uint32_t iar = *gicc(GICC_IAR);
        uint32_t irq = iar & 0x3FF; // bits [9:0] are the interrupt ID

        if (irq < 1020) {
            // Valid interrupt
            if (irq < MAX_IRQS && irq_handlers[irq]) {
                irq_handlers[irq](irq);
            }
            // Signal End of Interrupt
            *gicc(GICC_EOIR) = iar;
        }
        // irq == 1023 = spurious, ignore
    } else {
        // Synchronous exception or SError — panic
        const char* kind_str = "unknown";
        switch (kind) {
            case 0: kind_str = "synchronous"; break;
            case 1: kind_str = "IRQ";         break;
            case 2: kind_str = "FIQ";         break;
            case 3: kind_str = "SError";      break;
        }
        serial::printf("\n*** ARM64 EXCEPTION: kind=%s\n", kind_str);
        serial::printf("    ESR_EL1  = 0x%lx\n", frame->esr);
        serial::printf("    FAR_EL1  = 0x%lx\n", frame->far);
        serial::printf("    ELR_EL1  = 0x%lx  (PC at fault)\n", frame->pc);
        serial::printf("    SPSR_EL1 = 0x%lx\n", frame->pstate);
        serial::printf("    x0  = 0x%lx  x1  = 0x%lx\n",
                       frame->x[0], frame->x[1]);
        kernel_panic("Unhandled ARM64 exception");
    }
}

// ---- GIC initialisation ---------------------------------------------------

void init() {
    // ---- Distributor -------------------------------------------------------

    // Disable distributor while configuring
    *gicd(GICD_CTLR) = 0;
    asm volatile("dsb sy" ::: "memory");

    // Find out how many interrupt lines we have
    uint32_t typer = *gicd(GICD_TYPER);
    uint32_t it_lines = (typer & 0x1F) + 1; // ITLinesNumber
    uint32_t num_irqs = it_lines * 32;

    // Set all interrupts to:
    //   Group 0 (secure for EL1 signalled as IRQ with GIC_CTLR.FIQEn=0)
    //   Priority 0xA0 (high enough to pass the CPU priority mask)
    //   Target CPU0
    //   Level sensitive, 1-N model
    for (uint32_t i = 0; i < num_irqs / 32; i++) {
        *gicd(GICD_IGROUPR0 + i * 4)    = 0x00000000; // Group 0
        *gicd(GICD_ICENABLER0 + i * 4)  = 0xFFFFFFFF; // All disabled
        *gicd(GICD_ICPENDR0 + i * 4)    = 0xFFFFFFFF; // Clear pending
    }
    for (uint32_t i = 0; i < num_irqs / 4; i++) {
        *gicd(GICD_IPRIORITYR0 + i * 4)  = 0xA0A0A0A0; // Priority
        *gicd(GICD_ITARGETSR0  + i * 4)  = 0x01010101; // CPU 0
    }

    // Enable distributor
    *gicd(GICD_CTLR) = 1;

    // ---- CPU interface -----------------------------------------------------

    // Priority mask: accept all interrupts with priority < 0xFF (= all)
    *gicc(GICC_PMR) = 0xFF;

    // Enable CPU interface
    *gicc(GICC_CTLR) = 1;

    asm volatile("dsb sy\n\tisb" ::: "memory");

    serial::printf("       GICv2 init: %u IRQ lines\n", num_irqs);
}

void register_irq(uint32_t irq, void (*handler)(uint32_t)) {
    if (irq >= MAX_IRQS) return;
    irq_handlers[irq] = handler;

    // Enable this IRQ in the distributor
    uint32_t reg_idx = irq / 32;
    uint32_t bit     = 1U << (irq % 32);
    *gicd(GICD_ISENABLER0 + reg_idx * 4) = bit;
}

} // namespace exceptions
