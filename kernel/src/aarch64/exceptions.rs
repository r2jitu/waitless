// kernel/exceptions.rs — ARM64 exception handling + GIC init
//
// Installs the vector table (defined in boot.S) and initialises the ARM GIC
// so we can receive IRQs. Supports both GICv2 (QEMU virt) and GICv3 (HVF
// and modern QEMU configurations).
//
// On x86_64 this module provides no-op stubs.

// ============================================================================
// aarch64 implementation
// ============================================================================

#[cfg(target_arch = "aarch64")]
mod aarch64 {
    use core::arch::asm;

    use crate::aarch64::fdt;
    use crate::mmio::{self, ReadOnly, ReadWrite};
    use crate::once::InitOnce;
    use crate::serial;

    // ---- GIC register layouts ─────────────────────────────────────────────
    //
    // Per ARM Generic Interrupt Controller v2/v3 architecture spec. Only
    // the registers actually accessed by this driver are named; the rest
    // are explicit `_pad` arrays so the offsets compile-check against the
    // struct layout.

    /// GIC distributor register block. Covers offsets 0x0000..0x0BFF
    /// (the part this driver touches outside of IROUTER). IROUTER lives
    /// at +0x6100 and is accessed via a separate helper since putting it
    /// in this struct would require ~21KB of `_pad`.
    #[repr(C)]
    struct GicdRegs {
        ctlr: ReadWrite<u32>,              // 0x000
        typer: ReadOnly<u32>,              // 0x004
        _pad_008: [u32; 30],               // 0x008..0x07F
        _igroupr: [ReadWrite<u32>; 32],    // 0x080..0x0FF (kept for layout)
        isenabler: [ReadWrite<u32>; 32],   // 0x100..0x17F
        icenabler: [ReadWrite<u32>; 32],   // 0x180..0x1FF
        _pad_200: [u32; 32],               // 0x200..0x27F (ISPENDR)
        icpendr: [ReadWrite<u32>; 32],     // 0x280..0x2FF
        _pad_300: [u32; 64],               // 0x300..0x3FF
        ipriorityr: [ReadWrite<u32>; 256], // 0x400..0x7FF
        itargetsr: [ReadWrite<u32>; 256],  // 0x800..0xBFF (GICv2 only for SPIs)
    }

    // We do also write a GICv3 SPI router at offset 0x6100+8*intid. That's
    // 21 KB beyond the end of GicdRegs; put it in its own struct anchored
    // at +0x6100 from the distributor base.
    #[repr(C)]
    struct GicdIrouter {
        irouter: [ReadWrite<u64>; 988],    // 0x6100..0x7FD0 (32..1019 SPIs)
    }

    /// GICv2 CPU interface register block (also used as the per-CPU
    /// interface accessed via the banked alias).
    #[repr(C)]
    struct GiccRegs {
        ctlr: ReadWrite<u32>,              // 0x000
        pmr: ReadWrite<u32>,               // 0x004
        _bpr: u32,                         // 0x008
        iar: ReadOnly<u32>,                // 0x00C
        eoir: ReadWrite<u32>,              // 0x010
    }

    /// GICv3 redistributor frame: top 64KB for the RD region (we only
    /// touch GICR_WAKER at offset 0x014). The SGI/PPI configuration
    /// frame lives at +0x10000 from the same base.
    #[repr(C)]
    struct GicrRdFrame {
        _pad_000: [u32; 5],                // 0x000..0x013
        waker: ReadWrite<u32>,             // 0x014
    }

    #[repr(C)]
    struct GicrSgiFrame {
        _pad_000: [u32; 64],               // 0x000..0x0FF
        isenabler0: ReadWrite<u32>,        // 0x100 (corresponds to GICD_ISENABLER0 in the SGI frame)
    }

    // Compile-time layout assertions.
    const _: () = assert!(core::mem::size_of::<GicdRegs>() == 0xC00);
    const _: () = assert!(core::mem::size_of::<GiccRegs>() == 0x14);
    const _: () = assert!(core::mem::offset_of!(GicrRdFrame, waker) == 0x14);
    const _: () = assert!(core::mem::offset_of!(GicrSgiFrame, isenabler0) == 0x100);

    /// Resolved GIC bases. Populated exactly once on the BSP via `init()`
    /// before any AP starts; read by every core for MMIO access.
    struct GicConfig {
        gicd_base: u64,
        gicc_base: u64, // GICv2 only (computed as gicd_base + 0x10000)
        gicr_base: u64, // GICv3 only
        version: u8,
    }
    static GIC: InitOnce<GicConfig> = InitOnce::new();

    #[inline] fn gicd_base() -> u64 { GIC.get().gicd_base }
    #[inline] fn gicc_base() -> u64 { GIC.get().gicc_base }
    #[inline] fn gicr_base() -> u64 { GIC.get().gicr_base }
    #[inline] fn gic_version() -> u8 { GIC.get().version }

    #[inline]
    fn gicd() -> &'static GicdRegs {
        // SAFETY: GIC is initialised once via init(); the address comes
        // from the FDT and matches the GIC distributor layout.
        unsafe { mmio::at::<GicdRegs>(gicd_base()) }
    }
    #[inline]
    fn gicd_irouter() -> &'static GicdIrouter {
        unsafe { mmio::at::<GicdIrouter>(gicd_base() + 0x6100) }
    }
    #[inline]
    fn gicc() -> &'static GiccRegs {
        unsafe { mmio::at::<GiccRegs>(gicc_base()) }
    }

    // GICv3 distributor CTLR bits
    const GICD_CTLR_ARE_NS: u32 = 1 << 4;
    const GICD_CTLR_ENABLE_GRP1_NS: u32 = 1 << 1;

    /// Per-CPU redistributor frame stride (RD + SGI = 0x20000).
    const GICR_FRAME_STRIDE: u64 = 0x20000;
    /// Offset from RD frame base to SGI/PPI configuration frame.
    const GICR_SGI_OFFSET: u64 = 0x10000;

    // ---- IRQ handler table ------------------------------------------------

    const MAX_IRQS: usize = 256;

    // IRQ handler table. Registered on the BSP during boot via
    // `register_irq_handler`; read from the exception handler on any
    // core. Per-slot writes + reads are single-word and tearing-safe
    // on aarch64. Wrapped in `UnsafeCell` + `unsafe impl Sync`.
    struct IrqHandlersSlot(core::cell::UnsafeCell<[Option<fn(u32)>; MAX_IRQS]>);
    // SAFETY: single-writer (BSP) with single-word slot stores; readers
    // only observe fully-published handler pointers.
    unsafe impl Sync for IrqHandlersSlot {}

    static IRQ_HANDLERS: IrqHandlersSlot =
        IrqHandlersSlot(core::cell::UnsafeCell::new([None; MAX_IRQS]));

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
            let ver = if GIC.is_initialized() { gic_version() } else { 0 };
            if ver == 3 {
                let iar: u64;
                asm!("mrs {}, ICC_IAR1_EL1", out(reg) iar);
                let intid = (iar & 0xFF_FFFF) as u32;
                if intid < 1020 {
                    if (intid as usize) < MAX_IRQS {
                        if let Some(handler) = (*IRQ_HANDLERS.0.get())[intid as usize] {
                            handler(intid);
                        }
                    }
                    asm!("msr ICC_EOIR1_EL1, {}", in(reg) iar);
                }
            } else if ver == 2 {
                let iar = gicc().iar.read();
                let irq = iar & 0x3FF;
                if irq < 1020 {
                    if (irq as usize) < MAX_IRQS {
                        if let Some(handler) = (*IRQ_HANDLERS.0.get())[irq as usize] {
                            handler(irq);
                        }
                    }
                    gicc().eoir.write(iar);
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
        let d = gicd();
        let c = gicc();

        // Disable distributor while configuring
        d.ctlr.write(0);
        unsafe { asm!("dsb sy", options(nostack)); }

        let typer = d.typer.read();
        let it_lines = (typer & 0x1F) + 1;
        let num_irqs = it_lines * 32;

        for i in 0..(num_irqs / 32) as usize {
            d._igroupr[i].write(0x0000_0000);   // Group 0
            d.icenabler[i].write(0xFFFF_FFFF);  // All disabled
            d.icpendr[i].write(0xFFFF_FFFF);    // Clear pending
        }
        for i in 0..(num_irqs / 4) as usize {
            d.ipriorityr[i].write(0xA0A0_A0A0);
            d.itargetsr[i].write(0x0101_0101);
        }

        d.ctlr.write(1);
        c.pmr.write(0xFF);
        c.ctlr.write(1);
        unsafe { asm!("dsb sy", "isb", options(nostack)); }

        klog!("       GICv2 init: {} IRQ lines\n", num_irqs);
    }

    // ---- GICv3 initialisation ---------------------------------------------

    unsafe fn init_gicv3() {
        let d = gicd();
        let typer = d.typer.read();
        let it_lines = (typer & 0x1F) + 1;
        let num_irqs = it_lines * 32;

        // Check if the distributor is already configured — some hypervisors
        // (notably HVF's native vGIC) pre-init it and we should not stomp.
        let ctlr = d.ctlr.read();
        let already_configured = (ctlr & GICD_CTLR_ENABLE_GRP1_NS) != 0;

        if !already_configured {
            // Redistributor: wake up CPU 0's frame
            if gicr_base() != 0 {
                // SAFETY: redist base resolved from FDT; first frame is CPU 0.
                let rd = unsafe { mmio::at::<GicrRdFrame>(gicr_base()) };
                let waker = rd.waker.read();
                rd.waker.write(waker & !(1 << 1)); // Clear ProcessorSleep
                for _ in 0..1_000_000 {
                    if (rd.waker.read() & (1 << 2)) == 0 {
                        break;
                    }
                    unsafe { asm!("nop", options(nomem, nostack)); }
                }
            }

            // Full distributor init (QEMU, bare metal)
            d.ctlr.write(0);
            unsafe { asm!("dsb sy", options(nostack)); }

            for i in 1..(num_irqs / 32) as usize {
                d._igroupr[i].write(0xFFFF_FFFF);   // Group 1 NS
                d.icenabler[i].write(0xFFFF_FFFF);  // Disabled
                d.icpendr[i].write(0xFFFF_FFFF);    // Clear pending
            }
            for i in 8..(num_irqs / 4) as usize {
                d.ipriorityr[i].write(0xA0A0_A0A0);
            }

            // Route all SPIs to affinity 0.0.0.0 (CPU 0). GICv3 IROUTER
            // exists only for SPIs (INTID 32..1019), so cap the loop at
            // 1020 even if num_irqs reports more lines.
            let irouter = gicd_irouter();
            let last_spi = num_irqs.min(1020);
            for intid in 32..last_spi {
                irouter.irouter[(intid - 32) as usize].write(0);
            }

            d.ctlr.write(GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_GRP1_NS);
            unsafe { asm!("dsb sy", options(nostack)); }
            klog!("       GICv3 init: {} IRQ lines (full)\n", num_irqs);
        } else {
            klog!("       GICv3 init: {} IRQ lines (vGIC pre-configured)\n", num_irqs);
        }

        // CPU interface (system registers) — always needed.
        // SAFETY: writing to ICC_* system registers is privileged but
        // that is exactly what GIC init does; we are at EL1 with the
        // system registers we control.
        unsafe {
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
            // GICv2 CPU interface lives at GICD + 0x10000 (banked per-CPU);
            // GICv3 doesn't use it. Compute eagerly so the InitOnce holds
            // the full configuration.
            GIC.init(GicConfig {
                gicd_base: fdt.gic_dist_base,
                gicc_base: fdt.gic_dist_base.wrapping_add(0x10000),
                gicr_base: fdt.gic_redist_base,
                version: fdt.gic_version,
            });

            let v = gic_version();
            if v == 3 {
                init_gicv3();
            } else if v == 2 {
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
            if gic_version() == 2 {
                // GICv2: CPU interface is at GICD_BASE + 0x10000 (banked per-CPU)
                let c = gicc();
                c.ctlr.write(1);     // Enable CPU interface
                c.pmr.write(0xFF);   // All priorities
                return;
            }

            if gic_version() != 3 || gicr_base() == 0 {
                return;
            }

            // Each redistributor frame is 0x20000 bytes apart
            let cpu = crate::aarch64::smp::cpu_id() as u64;
            let gicr_frame = gicr_base() + cpu * GICR_FRAME_STRIDE;

            // Wake this core's redistributor.
            // SAFETY: gicr_frame is a per-CPU GICR RD frame.
            let rd = mmio::at::<GicrRdFrame>(gicr_frame);
            let waker = rd.waker.read();
            rd.waker.write(waker & !(1 << 1));
            for _ in 0..1_000_000 {
                if (rd.waker.read() & (1 << 2)) == 0 {
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
            (*IRQ_HANDLERS.0.get())[irq as usize] = Some(handler);

            if !GIC.is_initialized() || gicd_base() == 0 {
                return;
            }

            let reg_idx = (irq / 32) as usize;
            let bit = 1u32 << (irq % 32);

            if irq < 32 && gic_version() == 3 && gicr_base() != 0 {
                // GICv3: PPIs/SGIs (INTID 0-31) are in the GICR SGI frame.
                // Use this CPU's redistributor frame (each is 0x20000 bytes apart).
                // Bug fix: must NOT use GICR_BASE directly — that is CPU 0's frame.
                // APs must enable their SGIs in their own GICR frame.
                let cpu = crate::aarch64::smp::cpu_id() as u64;
                let sgi_frame_base = gicr_base() + cpu * GICR_FRAME_STRIDE + GICR_SGI_OFFSET;
                let sgi = mmio::at::<GicrSgiFrame>(sgi_frame_base);
                sgi.isenabler0.write(bit);
            } else {
                // SPIs (INTID >= 32) or GICv2: enable in the distributor
                gicd().isenabler[reg_idx].write(bit);
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
/// On x86_64 this is a no-op — IDT registration goes through `uni_kernel::x86_64::idt`.
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
