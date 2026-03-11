#pragma once
// kernel/aarch64/arch.h — ARM64 architecture primitives
//
// Provides the same API surface as the x86_64 version but using:
//   • MMIO (volatile pointer reads/writes) instead of I/O ports
//   • ARM system register access (mrs/msr)
//   • ARM memory barriers (dsb, isb, dmb)
//   • WFE/WFI for halt instead of HLT

#include <stdint.h>

namespace arch {

// ---- Memory barriers -------------------------------------------------------

static inline void dsb_sy() { asm volatile("dsb sy" ::: "memory"); }
static inline void dsb_st() { asm volatile("dsb st" ::: "memory"); }
static inline void dsb_ld() { asm volatile("dsb ld" ::: "memory"); }
static inline void isb() { asm volatile("isb" ::: "memory"); }
static inline void dmb_sy() { asm volatile("dmb sy" ::: "memory"); }

// ---- Interrupt control -----------------------------------------------------

static inline void cli() { asm volatile("msr daifset, #0xf" ::: "memory"); }
static inline void sti() { asm volatile("msr daifclr, #0xf" ::: "memory"); }
static inline void hlt() { asm volatile("wfe"); }
static inline void wfi() { asm volatile("wfi"); }

// Power off the machine via PSCI SYSTEM_OFF (HVC call, function 0x84000008).
// QEMU's virt machine handles this and terminates the emulator cleanly.
// Never returns.
[[noreturn]] static inline void shutdown() {
  asm volatile("movz x0, #0x8400, lsl #16\n\t" // x0  = 0x84000000
               "movk x0, #0x0008\n\t"          // x0 |= 0x00000008 → 0x84000008
               "hvc #0\n\t"                    // PSCI SYSTEM_OFF
               ::
                   : "x0", "memory");
  while (true)
    asm volatile("wfi");
}

// ---- MMIO access -----------------------------------------------------------
// All device registers are memory-mapped on ARM64.

static inline uint8_t mmio_read8(uint64_t addr) {
  return *reinterpret_cast<volatile uint8_t *>(addr);
}
static inline uint16_t mmio_read16(uint64_t addr) {
  return *reinterpret_cast<volatile uint16_t *>(addr);
}
static inline uint32_t mmio_read32(uint64_t addr) {
  return *reinterpret_cast<volatile uint32_t *>(addr);
}
static inline uint64_t mmio_read64(uint64_t addr) {
  return *reinterpret_cast<volatile uint64_t *>(addr);
}

static inline void mmio_write8(uint64_t addr, uint8_t val) {
  *reinterpret_cast<volatile uint8_t *>(addr) = val;
}
static inline void mmio_write16(uint64_t addr, uint16_t val) {
  *reinterpret_cast<volatile uint16_t *>(addr) = val;
}
static inline void mmio_write32(uint64_t addr, uint32_t val) {
  *reinterpret_cast<volatile uint32_t *>(addr) = val;
}
static inline void mmio_write64(uint64_t addr, uint64_t val) {
  *reinterpret_cast<volatile uint64_t *>(addr) = val;
}

// ---- Stub I/O-port functions (no-ops on ARM, satisfy shared headers) -------
static inline uint8_t inb(uint16_t) { return 0; }
static inline uint16_t inw(uint16_t) { return 0; }
static inline uint32_t inl(uint16_t) { return 0; }
static inline void outb(uint16_t, uint8_t) {}
static inline void outw(uint16_t, uint16_t) {}
static inline void outl(uint16_t, uint32_t) {}
static inline void io_wait() {}

// ---- Virtio register I/O — ARM64 uses MMIO (not I/O ports) ----------------
// virtio.cc calls these helpers so it compiles identically on both arches.

static inline uint8_t virtio_read8(uint64_t base) { return mmio_read8(base); }
static inline uint16_t virtio_read16(uint64_t base) {
  return mmio_read16(base);
}
static inline uint32_t virtio_read32(uint64_t base) {
  return mmio_read32(base);
}
static inline void virtio_write8(uint64_t base, uint8_t v) {
  mmio_write8(base, v);
}
static inline void virtio_write16(uint64_t base, uint16_t v) {
  mmio_write16(base, v);
}
static inline void virtio_write32(uint64_t base, uint32_t v) {
  mmio_write32(base, v);
}

// Hint to the CPU to reduce power during a spin-wait loop.
static inline void cpu_relax() { asm volatile("yield" ::: "memory"); }

// Mask/unmask IRQ (DAIF.I only — never touch FIQ, VZ uses it for hypervisor).
// Used by the idle pattern: mask → check ring → WFI → unmask.
static inline void mask_irq() { asm volatile("msr daifset, #0x2" ::: "memory"); }
static inline void unmask_irq() { asm volatile("msr daifclr, #0x2" ::: "memory"); }

// Suspend until the next interrupt.  WFI wakes on any pending GIC interrupt
// even when DAIF.I is set (IRQs masked at CPU level).  The caller uses the
// mask→check→WFI→unmask pattern to avoid the race where an interrupt fires
// and gets handled between the ring check and WFI.
static inline void idle() { asm volatile("wfi" ::: "memory"); }

// ---- ARM generic timer (for busy-wait timeouts) ----------------------------

static inline uint64_t read_cntpct() {
  uint64_t val;
  asm volatile("mrs %0, cntpct_el0" : "=r"(val));
  return val;
}
static inline uint64_t read_cntfrq() {
  uint64_t val;
  asm volatile("mrs %0, cntfrq_el0" : "=r"(val));
  return val;
}

// Busy-wait for approximately `microseconds` microseconds.
static inline void udelay(uint64_t microseconds) {
  uint64_t freq = read_cntfrq();
  uint64_t ticks = (freq / 1000000ULL) * microseconds;
  uint64_t end = read_cntpct() + ticks;
  while (read_cntpct() < end) {
    asm volatile("nop");
  }
}

// ---- TLB invalidation ------------------------------------------------------

static inline void invlpg(void *) {
  asm volatile("tlbi vmalle1is\n\t"
               "dsb  sy\n\t"
               "isb" ::
                   : "memory");
}

// ---- No-op stubs for x86-specific operations used in shared code -----------

struct GDTR {
  uint16_t limit;
  uint64_t base;
} __attribute__((packed));
struct IDTR {
  uint16_t limit;
  uint64_t base;
} __attribute__((packed));

static inline void lgdt(const GDTR &) {}
static inline void lidt(const IDTR &) {}
static inline void ltr(uint16_t) {}

static inline uint64_t rdmsr(uint32_t) { return 0; }
static inline void wrmsr(uint32_t, uint64_t) {}
static inline uint64_t read_cr2() { return 0; }
static inline uint64_t read_cr3() { return 0; }
static inline void write_cr3(uint64_t) {}

} // namespace arch
