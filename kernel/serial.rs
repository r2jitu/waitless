// kernel/serial.rs — Serial console driver (Rust, no_std)
//
// Supports two architectures:
//
//   x86_64: COM1 serial port (I/O port 0x3F8), 115200 baud, 8N1.
//
//   aarch64: Runtime backend selection based on FDT discovery:
//     - PL011 UART (QEMU "virt" machine)
//     - VirtIO console (VZ.framework or any PCI platform)
//     - Falls back to no-op if nothing found.
//
// Provides a core::fmt::Write implementation (SerialWriter) for formatted
// Rust output, plus puts() for byte-slice logging.

// ============================================================================
// x86_64: COM1 port I/O serial
// ============================================================================

#[cfg(target_arch = "x86_64")]
mod x86 {
    use core::arch::asm;

    const COM1: u16 = 0x3F8;
    const RBR: u16 = 0; // Receive Buffer Register (read, DLAB=0)
    const THR: u16 = 0; // Transmit Holding Register (write, DLAB=0)
    const DLL: u16 = 0; // Divisor Latch Low (DLAB=1)
    const DLH: u16 = 1; // Divisor Latch High (DLAB=1)
    const IER: u16 = 1; // Interrupt Enable Register (DLAB=0)
    const FCR: u16 = 2; // FIFO Control Register (write)
    const LCR: u16 = 3; // Line Control Register
    const MCR: u16 = 4; // Modem Control Register
    const LSR: u16 = 5; // Line Status Register

    #[inline(always)]
    unsafe fn outb(port: u16, val: u8) {
        unsafe {
            asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
        }
    }

    #[inline(always)]
    unsafe fn inb(port: u16) -> u8 {
        unsafe {
            let ret: u8;
            asm!("in al, dx", out("al") ret, in("dx") port, options(nomem, nostack));
            ret
        }
    }

    pub unsafe fn init() {
        unsafe {
            // Disable all UART interrupts
            outb(COM1 + IER, 0x00);
            // Enable DLAB to set baud rate
            outb(COM1 + LCR, 0x80);
            // Set divisor to 1 (115200 baud)
            outb(COM1 + DLL, 0x01);
            outb(COM1 + DLH, 0x00);
            // 8N1, clear DLAB
            outb(COM1 + LCR, 0x03);
            // Enable FIFO, clear queues, 14-byte threshold
            outb(COM1 + FCR, 0xC7);
            // RTS/DSR + OUT2 (required for interrupts)
            outb(COM1 + MCR, 0x0B);
        }
    }

    pub unsafe fn putc(c: u8) {
        unsafe {
            // Wait for THR empty (LSR bit 5)
            while (inb(COM1 + LSR) & 0x20) == 0 {}
            outb(COM1 + THR, c);
        }
    }

    pub unsafe fn try_getc() -> i32 {
        unsafe {
            // LSR bit 0 = Data Ready
            if (inb(COM1 + LSR) & 0x01) != 0 {
                inb(COM1 + RBR) as i32
            } else {
                -1
            }
        }
    }

    pub unsafe fn enable_rx_irq() {
        unsafe {
            // Enable ERBFI (Received Data Available Interrupt)
            outb(COM1 + IER, 0x01);
        }
    }
}

// ============================================================================
// aarch64: PL011 UART + VirtIO console backends
// ============================================================================

#[cfg(target_arch = "aarch64")]
mod aarch64 {
    use crate::aarch64::fdt;
    use crate::mmio::{self, ReadOnly, ReadWrite, WriteOnly};

    // ── PL011 PrimeCell UART register layout ──────────────────────────────
    //
    // Per ARM PrimeCell PL011 r1p5 TRM. Only the registers we use are
    // accessed; the rest are reserved-but-named for clarity.
    #[repr(C)]
    struct Pl011Regs {
        dr: ReadWrite<u32>,            // 0x000 Data register
        _rsr_ecr: u32,                 // 0x004 Receive Status / Error Clear
        _reserved0: [u32; 4],          // 0x008–0x014
        fr: ReadOnly<u32>,             // 0x018 Flag register
        _reserved1: u32,               // 0x01C
        _ilpr: u32,                    // 0x020
        ibrd: WriteOnly<u32>,          // 0x024 Integer baud rate divisor
        fbrd: WriteOnly<u32>,          // 0x028 Fractional baud rate divisor
        lcr_h: WriteOnly<u32>,         // 0x02C Line control
        cr: ReadWrite<u32>,            // 0x030 Control
    }

    const FR_TXFF: u32 = 1 << 5; // TX FIFO full
    const FR_RXFE: u32 = 1 << 4; // RX FIFO empty
    const CR_UARTEN: u32 = 1 << 0;
    const CR_TXE: u32 = 1 << 8;
    const CR_RXE: u32 = 1 << 9;

    /// Serial backend, encoded as a `u8` so it can live in an `AtomicU8`:
    /// 0 = None, 1 = Pl011, 2 = Virtio. Set during `init()` on the BSP
    /// and read by every core.
    const BACKEND_NONE: u8 = 0;
    const BACKEND_PL011: u8 = 1;
    const BACKEND_VIRTIO: u8 = 2;
    static BACKEND: core::sync::atomic::AtomicU8 =
        core::sync::atomic::AtomicU8::new(BACKEND_NONE);

    /// Resolved PL011 register handle. Populated by `pl011_init` after
    /// FDT discovery; read by every PL011 access. Stored as the raw
    /// base address (AtomicU64) since the typed reference can't go
    /// into a static directly without an unsafe const initializer.
    static PL011_BASE: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);

    #[inline(always)]
    fn pl011() -> &'static Pl011Regs {
        let base = PL011_BASE.load(core::sync::atomic::Ordering::Relaxed);
        // SAFETY: PL011_BASE is set exactly once in pl011_init from a
        // valid FDT-discovered MMIO base; subsequent loads return the
        // same address. The Pl011Regs layout matches the ARM TRM.
        unsafe { mmio::at::<Pl011Regs>(base) }
    }

    unsafe extern "C" {
        fn pci_init();
        fn virtio_console_init_mmio(base_addr: u64) -> bool;
        fn virtio_console_init_pci() -> bool;
        fn virtio_console_putc(c: u8);
        fn virtio_console_try_getc() -> i32;
    }

    fn pl011_init(base: u64) {
        PL011_BASE.store(base, core::sync::atomic::Ordering::Release);
        let r = pl011();
        r.cr.write(0);                      // disable UART
        r.ibrd.write(13);                   // 115200 @ 24 MHz
        r.fbrd.write(1);
        r.lcr_h.write((3 << 5) | (1 << 4)); // 8N1, FIFO on
        r.cr.write(CR_UARTEN | CR_TXE | CR_RXE);
        BACKEND.store(BACKEND_PL011, core::sync::atomic::Ordering::Release);
    }

    pub unsafe fn init() {
        unsafe {
            let fdt = fdt::info();

            // Prefer PL011 if FDT found one (QEMU path)
            if fdt.uart_base != 0 {
                pl011_init(fdt.uart_base);
                return;
            }

            // Try virtio-mmio console if FDT found virtio-mmio devices
            if fdt.virtio_count > 0 {
                for i in 0..fdt.virtio_count as usize {
                    if virtio_console_init_mmio(fdt.virtio_bases[i]) {
                        BACKEND.store(BACKEND_VIRTIO, core::sync::atomic::Ordering::Release);
                        return;
                    }
                }
            }

            // PCI VirtIO console (VZ.framework and other PCI platforms)
            if fdt.pcie_ecam_base != 0 {
                pci_init();
                if virtio_console_init_pci() {
                    BACKEND.store(BACKEND_VIRTIO, core::sync::atomic::Ordering::Release);
                    return;
                }
            }

            // No console found — putc() is a no-op, kernel runs silently.
        }
    }

    pub unsafe fn putc(c: u8) {
        match BACKEND.load(core::sync::atomic::Ordering::Acquire) {
            BACKEND_VIRTIO => unsafe { virtio_console_putc(c) },
            BACKEND_PL011 => {
                let r = pl011();
                // Wait for TX FIFO not full
                while (r.fr.read() & FR_TXFF) != 0 {}
                r.dr.write(c as u32);
            }
            _ => {}
        }
    }

    pub unsafe fn try_getc() -> i32 {
        match BACKEND.load(core::sync::atomic::Ordering::Acquire) {
            BACKEND_VIRTIO => unsafe { virtio_console_try_getc() },
            BACKEND_PL011 => {
                let r = pl011();
                if (r.fr.read() & FR_RXFE) == 0 {
                    (r.dr.read() & 0xFF) as i32
                } else {
                    -1
                }
            }
            _ => -1,
        }
    }
}

// ============================================================================
// Common serial API
// ============================================================================

static SHUTDOWN_REQUESTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Serial-write spinlock. Serialises whole `puts`/`putc` calls so multi-core
/// log output isn't interleaved or torn (the underlying COM1/PL011 ports
/// take a single byte per cycle, but the VirtIO console backend has a
/// shared TX descriptor ring that races on `static mut` indices if two
/// cores write concurrently).
///
/// On QEMU/KVM and x86_64 use real CAS. On vz_compat (atomic RMW faults
/// on guest RAM) skip the lock entirely and instead restrict console
/// output to the BSP only — APs return without printing. This preserves
/// the previous aarch64 behaviour while removing the latent
/// `static mut`-based data race for everyone else.
#[cfg(not(vz_compat))]
static SERIAL_TX_LOCK: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// RAII guard for the serial TX spinlock. Acquired by `SerialTxGuard::new`,
/// released automatically on `Drop`. Can't forget to release; can't
/// double-release. Zero cost — `Drop::drop` inlines to one
/// `store(false, Release)`, the same code the manual `serial_unlock`
/// produced.
///
/// On vz_compat the spinlock is replaced with a BSP-only check (atomic
/// RMW faults on guest RAM); the guard is still constructed but
/// `held = false` so its drop is a no-op.
#[must_use = "the guard releases the lock when dropped; binding to _ would release it immediately"]
pub(crate) struct SerialTxGuard {
    held: bool,
}

impl SerialTxGuard {
    /// Acquire the lock. On QEMU/KVM spins until CAS succeeds. On
    /// vz_compat (`held = false`) returns immediately and the guard
    /// is a no-op; callers must check `is_held()` before performing
    /// the actual TX (or rely on the BSP-only path in puts/putc).
    #[inline]
    pub(crate) fn new() -> Self {
        #[cfg(not(vz_compat))]
        {
            use core::sync::atomic::Ordering;
            while SERIAL_TX_LOCK
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            SerialTxGuard { held: true }
        }
        #[cfg(vz_compat)]
        {
            SerialTxGuard { held: false }
        }
    }
}

impl Drop for SerialTxGuard {
    #[inline]
    fn drop(&mut self) {
        #[cfg(not(vz_compat))]
        if self.held {
            SERIAL_TX_LOCK.store(false, core::sync::atomic::Ordering::Release);
        }
        #[cfg(vz_compat)]
        let _ = self.held;
    }
}

/// On vz_compat we cannot take a real lock; restrict console TX to the BSP.
#[cfg(vz_compat)]
fn vz_is_bsp() -> bool {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let mpidr: u64;
        core::arch::asm!("mrs {}, MPIDR_EL1", out(reg) mpidr, options(nomem, nostack));
        (mpidr & 0xFF) == 0
    }
    #[cfg(not(target_arch = "aarch64"))]
    { true }
}

pub fn init() {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        x86::init();
        #[cfg(target_arch = "aarch64")]
        aarch64::init();
    }
}

pub fn putc(c: u8) {
    #[cfg(vz_compat)]
    if !vz_is_bsp() { return; }
    let _guard = SerialTxGuard::new();
    unsafe {
        #[cfg(target_arch = "x86_64")]
        x86::putc(c);
        #[cfg(target_arch = "aarch64")]
        aarch64::putc(c);
    }
    // _guard released at end of scope.
}

pub fn puts(s: &[u8]) {
    #[cfg(vz_compat)]
    if !vz_is_bsp() { return; }
    // Take the lock once around the whole string so multi-core log lines
    // don't interleave at byte granularity. RAII releases on scope exit.
    let _guard = SerialTxGuard::new();
    for &c in s {
        if c == b'\n' { unsafe {
            #[cfg(target_arch = "x86_64")] x86::putc(b'\r');
            #[cfg(target_arch = "aarch64")] aarch64::putc(b'\r');
        }}
        unsafe {
            #[cfg(target_arch = "x86_64")] x86::putc(c);
            #[cfg(target_arch = "aarch64")] aarch64::putc(c);
        }
    }
}

pub fn try_getc() -> i32 {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        { x86::try_getc() }
        #[cfg(target_arch = "aarch64")]
        { aarch64::try_getc() }
    }
}

pub fn check_shutdown() -> bool {
    if SHUTDOWN_REQUESTED.load(core::sync::atomic::Ordering::Relaxed) {
        return true;
    }
    loop {
        let c = try_getc();
        if c < 0 {
            break;
        }
        if c == 0x03 { // Ctrl-C
            SHUTDOWN_REQUESTED.store(true, core::sync::atomic::Ordering::Relaxed);
            return true;
        }
    }
    false
}

// x86_64-specific: RX interrupt support for idle wakeup on Ctrl-C
#[cfg(target_arch = "x86_64")]
pub fn enable_rx_irq() {
    unsafe { x86::enable_rx_irq(); }
}

#[cfg(target_arch = "x86_64")]
pub fn rx_isr() {
    // Drain RX FIFO to clear the UART interrupt condition
    loop {
        let c = unsafe { x86::try_getc() };
        if c < 0 {
            break;
        }
        if c == 0x03 {
            SHUTDOWN_REQUESTED.store(true, core::sync::atomic::Ordering::Relaxed);
        }
    }
}

// ============================================================================
// core::fmt::Write implementation for Rust callers
// ============================================================================

/// Serial writer for use with core::fmt::Write.
/// Usage: `write!(SerialWriter, "hello {}", 42)`
pub struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                putc(b'\r');
            }
            putc(b);
        }
        Ok(())
    }
}

/// Formatted serial output from Rust code.
pub fn write_fmt(args: core::fmt::Arguments) {
    use core::fmt::Write;
    let _ = SerialWriter.write_fmt(args);
}
