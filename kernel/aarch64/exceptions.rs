// kernel/exceptions.rs — ARM64 exception handling + GIC init
//
// Installs the vector table (defined in boot.S) and initialises the ARM GIC
// so we can receive IRQs.  Supports both GICv2 (QEMU virt) and GICv3 (Apple
// VZ.framework).
//
// On x86_64 this module provides no-op stubs.

// ============================================================================
// aarch64 implementation
// ============================================================================

#[cfg(target_arch = "aarch64")]
mod aarch64 {
    use core::arch::asm;
    use core::ptr;

    use crate::aarch64::fdt;
    use crate::serial;

    // ---- GIC register bases (filled from FDT at init time) ----------------

    static mut GICD_BASE: u64 = 0;
    static mut GICC_BASE: u64 = 0; // GICv2 only
    static mut GICR_BASE: u64 = 0; // GICv3 only
    static mut GIC_VERSION: u8 = 0;

    // ---- Distributor registers --------------------------------------------

    const GICD_CTLR: u32 = 0x000;
    const GICD_TYPER: u32 = 0x004;
    const GICD_IGROUPR0: u32 = 0x080;
    const GICD_ISENABLER0: u32 = 0x100;
    const GICD_ICENABLER0: u32 = 0x180;
    const GICD_ICPENDR0: u32 = 0x280;
    const GICD_IPRIORITYR0: u32 = 0x400;
    const GICD_ITARGETSR0: u32 = 0x800; // GICv2 only

    // GICv3 distributor CTLR bits
    const GICD_CTLR_ARE_NS: u32 = 1 << 4;
    const GICD_CTLR_ENABLE_GRP1_NS: u32 = 1 << 1;

    // GICv3: SPI affinity routing
    const GICD_IROUTER_BASE: u32 = 0x6100; // first SPI = INTID 32

    // ---- GICv2 CPU interface registers ------------------------------------

    const GICC_CTLR: u32 = 0x000;
    const GICC_PMR: u32 = 0x004;
    const GICC_IAR: u32 = 0x00C;
    const GICC_EOIR: u32 = 0x010;

    // ---- GICv3 redistributor registers ------------------------------------

    const GICR_WAKER: u32 = 0x014;
    const GICR_SGI_BASE: u32 = 0x10000;

    // ---- MMIO helpers -----------------------------------------------------

    #[inline(always)]
    unsafe fn gicd_read(off: u32) -> u32 {
        unsafe { ptr::read_volatile((GICD_BASE + off as u64) as *const u32) }
    }

    #[inline(always)]
    unsafe fn gicd_write(off: u32, val: u32) {
        unsafe { ptr::write_volatile((GICD_BASE + off as u64) as *mut u32, val); }
    }

    #[inline(always)]
    unsafe fn gicc_read(off: u32) -> u32 {
        unsafe { ptr::read_volatile((GICC_BASE + off as u64) as *const u32) }
    }

    #[inline(always)]
    unsafe fn gicc_write(off: u32, val: u32) {
        unsafe { ptr::write_volatile((GICC_BASE + off as u64) as *mut u32, val); }
    }

    #[inline(always)]
    unsafe fn gicr_read(off: u32) -> u32 {
        unsafe { ptr::read_volatile((GICR_BASE + off as u64) as *const u32) }
    }

    #[inline(always)]
    unsafe fn gicr_write(off: u32, val: u32) {
        unsafe { ptr::write_volatile((GICR_BASE + off as u64) as *mut u32, val); }
    }

    // ---- IRQ handler table ------------------------------------------------

    const MAX_IRQS: usize = 256;
    static mut IRQ_HANDLERS: [Option<fn(u32)>; MAX_IRQS] = [None; MAX_IRQS];

    // ---- Exception handler (called from vector stubs in boot.S) -----------

    /// Exception frame pushed by boot.S vector stubs.
    #[repr(C)]
    pub struct Frame {
        esr: u64,
        far: u64,
        x: [u64; 31],
        sp: u64,
        pc: u64,
        pstate: u64,
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn exception_handler(kind: u32, frame: *const Frame) {
        unsafe {
        let frame = &*frame;

        if kind == 1 {
            // IRQ
            if GIC_VERSION == 3 {
                let iar: u64;
                asm!("mrs {}, ICC_IAR1_EL1", out(reg) iar);
                let intid = (iar & 0xFF_FFFF) as u32;
                if intid < 1020 {
                    if (intid as usize) < MAX_IRQS {
                        if let Some(handler) = IRQ_HANDLERS[intid as usize] {
                            handler(intid);
                        }
                    }
                    asm!("msr ICC_EOIR1_EL1, {}", in(reg) iar);
                }
            } else if GIC_VERSION == 2 {
                let iar = gicc_read(GICC_IAR);
                let irq = iar & 0x3FF;
                if irq < 1020 {
                    if (irq as usize) < MAX_IRQS {
                        if let Some(handler) = IRQ_HANDLERS[irq as usize] {
                            handler(irq);
                        }
                    }
                    gicc_write(GICC_EOIR, iar);
                }
            }
            // GIC_VERSION == 0: no GIC, WFI woke us, nothing to ack
        } else {
            let kind_str = match kind {
                0 => "synchronous",
                1 => "IRQ",
                2 => "FIQ",
                3 => "SError",
                _ => "unknown",
            };
            klog!("\n*** ARM64 EXCEPTION: kind={}\n", kind_str);
            klog!("    ESR_EL1  = 0x{:x}\n", frame.esr);
            klog!("    FAR_EL1  = 0x{:x}\n", frame.far);
            klog!("    ELR_EL1  = 0x{:x}  (PC at fault)\n", frame.pc);
            klog!("    SPSR_EL1 = 0x{:x}\n", frame.pstate);
            klog!("    x0  = 0x{:x}  x1  = 0x{:x}\n", frame.x[0], frame.x[1]);

            // Halt — unrecoverable
            serial::puts(b"\nSystem halted.\n");
            loop {
                asm!("wfe", options(nomem, nostack));
            }
        }
        }
    }

    // ---- Logging macro using serial ----------------------------------------

    macro_rules! klog {
        ($($arg:tt)*) => {
            serial::write_fmt(format_args!($($arg)*));
        };
    }
    use klog;

    // ---- GICv2 initialisation ---------------------------------------------

    unsafe fn init_gicv2() {
        unsafe {
        GICC_BASE = GICD_BASE + 0x10000;

        // Disable distributor while configuring
        gicd_write(GICD_CTLR, 0);
        asm!("dsb sy", options(nostack));

        let typer = gicd_read(GICD_TYPER);
        let it_lines = (typer & 0x1F) + 1;
        let num_irqs = it_lines * 32;

        for i in 0..num_irqs / 32 {
            gicd_write(GICD_IGROUPR0 + i * 4, 0x0000_0000);   // Group 0
            gicd_write(GICD_ICENABLER0 + i * 4, 0xFFFF_FFFF); // All disabled
            gicd_write(GICD_ICPENDR0 + i * 4, 0xFFFF_FFFF);   // Clear pending
        }
        for i in 0..num_irqs / 4 {
            gicd_write(GICD_IPRIORITYR0 + i * 4, 0xA0A0_A0A0);
            gicd_write(GICD_ITARGETSR0 + i * 4, 0x0101_0101);
        }

        gicd_write(GICD_CTLR, 1);
        gicc_write(GICC_PMR, 0xFF);
        gicc_write(GICC_CTLR, 1);
        asm!("dsb sy", "isb", options(nostack));

        klog!("       GICv2 init: {} IRQ lines\n", num_irqs);
        }
    }

    // ---- GICv3 initialisation ---------------------------------------------

    unsafe fn init_gicv3() {
        unsafe {
        let typer = gicd_read(GICD_TYPER);
        let it_lines = (typer & 0x1F) + 1;
        let num_irqs = it_lines * 32;

        // Check if distributor is already configured (VZ pre-inits vGIC)
        let ctlr = gicd_read(GICD_CTLR);
        let already_configured = (ctlr & GICD_CTLR_ENABLE_GRP1_NS) != 0;

        if !already_configured {
            // Redistributor: wake up CPU 0's frame
            if GICR_BASE != 0 {
                let waker = gicr_read(GICR_WAKER);
                gicr_write(GICR_WAKER, waker & !(1 << 1)); // Clear ProcessorSleep
                for _ in 0..1_000_000 {
                    if (gicr_read(GICR_WAKER) & (1 << 2)) == 0 {
                        break;
                    }
                    asm!("nop", options(nomem, nostack));
                }
            }

            // Full distributor init (QEMU, bare metal)
            gicd_write(GICD_CTLR, 0);
            asm!("dsb sy", options(nostack));

            for i in 1..num_irqs / 32 {
                gicd_write(GICD_IGROUPR0 + i * 4, 0xFFFF_FFFF);   // Group 1 NS
                gicd_write(GICD_ICENABLER0 + i * 4, 0xFFFF_FFFF); // Disabled
                gicd_write(GICD_ICPENDR0 + i * 4, 0xFFFF_FFFF);   // Clear pending
            }
            for i in 8..num_irqs / 4 {
                gicd_write(GICD_IPRIORITYR0 + i * 4, 0xA0A0_A0A0);
            }

            // Route all SPIs to affinity 0.0.0.0 (CPU 0)
            for intid in 32..num_irqs {
                let router_addr = GICD_BASE + GICD_IROUTER_BASE as u64 + (intid - 32) as u64 * 8;
                ptr::write_volatile(router_addr as *mut u64, 0);
            }

            gicd_write(GICD_CTLR, GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_GRP1_NS);
            asm!("dsb sy", options(nostack));
            klog!("       GICv3 init: {} IRQ lines (full)\n", num_irqs);
        } else {
            klog!("       GICv3 init: {} IRQ lines (vGIC pre-configured)\n", num_irqs);
        }

        // CPU interface (system registers) — always needed
        let sre: u64;
        asm!("mrs {}, ICC_SRE_EL1", out(reg) sre);
        asm!("msr ICC_SRE_EL1, {}", in(reg) sre | 1);
        asm!("isb", options(nostack));

        asm!("msr ICC_PMR_EL1, {}", in(reg) 0xFF_u64);
        asm!("msr ICC_BPR1_EL1, {}", in(reg) 0_u64);
        asm!("msr ICC_IGRPEN1_EL1, {}", in(reg) 1_u64);
        asm!("isb", options(nostack));
        }
    }

    // ---- Public interface --------------------------------------------------

    pub unsafe fn init() {
        unsafe {
            let fdt = fdt::info();
            GICD_BASE = fdt.gic_dist_base;
            GICR_BASE = fdt.gic_redist_base;
            GIC_VERSION = fdt.gic_version;

            if GIC_VERSION == 3 {
                init_gicv3();
            } else if GIC_VERSION == 2 {
                init_gicv2();
            } else {
                serial::puts(b"       GIC init skipped (no GIC in DTB)\n");
            }
        }
    }

    /// Initialize GICv3 CPU interface for a secondary core (AP).
    /// The distributor is already configured by core 0; APs only need
    /// their own redistributor + CPU interface registers.
    pub unsafe fn init_ap() {
        unsafe {
            if GIC_VERSION != 3 || GICR_BASE == 0 {
                return;
            }

            // Each redistributor frame is 0x20000 bytes apart
            let cpu = crate::aarch64::smp::cpu_id() as u64;
            let gicr_frame = GICR_BASE + cpu * 0x20000;

            // Wake this core's redistributor
            let waker_addr = gicr_frame + GICR_WAKER as u64;
            let waker = ptr::read_volatile(waker_addr as *const u32);
            ptr::write_volatile(waker_addr as *mut u32, waker & !(1 << 1));
            for _ in 0..1_000_000 {
                if (ptr::read_volatile(waker_addr as *const u32) & (1 << 2)) == 0 {
                    break;
                }
                asm!("nop", options(nomem, nostack));
            }

            // Enable CPU interface (system registers)
            let sre: u64;
            asm!("mrs {}, ICC_SRE_EL1", out(reg) sre);
            asm!("msr ICC_SRE_EL1, {}", in(reg) sre | 1);
            asm!("isb", options(nostack));
            asm!("msr ICC_PMR_EL1, {}", in(reg) 0xFF_u64);
            asm!("msr ICC_BPR1_EL1, {}", in(reg) 0_u64);
            asm!("msr ICC_IGRPEN1_EL1, {}", in(reg) 1_u64);
            asm!("isb", options(nostack));
        }
    }

    /// Timer PPI handler — disables the virtual timer so it doesn't re-fire.
    fn timer_wakeup_handler(_irq: u32) {
        unsafe { asm!("msr cntv_ctl_el0, {}", in(reg) 0_u64, options(nostack)); }
    }

    pub unsafe fn enable_timer_wakeup() {
        unsafe {
            register_irq(27, timer_wakeup_handler);
        }
    }

    pub unsafe fn register_irq(irq: u32, handler: fn(u32)) {
        unsafe {
            if (irq as usize) >= MAX_IRQS {
                return;
            }
            IRQ_HANDLERS[irq as usize] = Some(handler);

            if GICD_BASE == 0 {
                return;
            }

            let reg_idx = irq / 32;
            let bit = 1u32 << (irq % 32);

            if irq < 32 && GIC_VERSION == 3 && GICR_BASE != 0 {
                // GICv3: PPIs/SGIs (INTID 0-31) are in the GICR SGI frame
                let addr = GICR_BASE + GICR_SGI_BASE as u64 + GICD_ISENABLER0 as u64;
                ptr::write_volatile(addr as *mut u32, bit);
            } else {
                // SPIs (INTID >= 32) or GICv2: enable in the distributor
                gicd_write(GICD_ISENABLER0 + reg_idx * 4, bit);
            }
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Initialise the GIC (or no-op on x86_64).
pub fn init() {
    #[cfg(target_arch = "aarch64")]
    unsafe { aarch64::init(); }
}

/// Register an IRQ handler (aarch64 GIC).
/// On x86_64 this is a no-op — IDT registration goes through idt.cc.
pub fn register_irq(irq: u32, handler: fn(u32)) {
    #[cfg(target_arch = "aarch64")]
    unsafe { aarch64::register_irq(irq, handler); }
    #[cfg(not(target_arch = "aarch64"))]
    { let _ = (irq, handler); }
}

/// Enable the timer wakeup PPI (INTID 27) for idle().
pub fn enable_timer_wakeup() {
    #[cfg(target_arch = "aarch64")]
    unsafe { aarch64::enable_timer_wakeup(); }
}

/// Initialize GIC for a secondary core (AP).
pub fn init_ap() {
    #[cfg(target_arch = "aarch64")]
    unsafe { aarch64::init_ap(); }
}
