// kernel/serial.rs — Serial console driver (Rust, no_std)
//
// Supports two architectures:
//
//   x86_64: COM1 serial port (I/O port 0x3F8), 115200 baud, 8N1.
//
//   aarch64: Runtime backend selection based on FDT discovery:
//     - PL011 UART (QEMU "virt" machine, HVF runner)
//     - VirtIO console (PCI-based platforms)
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

    /// Discovered console backend. Set exactly once by `init()` on the
    /// BSP after FDT discovery, then read by every core. `InitOnce`
    /// gives us release/acquire publication and proper enum dispatch
    /// without magic-number constants.
    enum SerialBackend {
        Pl011 { base: u64 },
        Virtio,
    }

    static BACKEND: crate::once::InitOnce<SerialBackend> = crate::once::InitOnce::new();

    #[inline(always)]
    fn pl011_at(base: u64) -> &'static Pl011Regs {
        // SAFETY: caller passes a base discovered from the FDT, which
        // points at a valid PL011 device. The Pl011Regs layout matches
        // the ARM TRM.
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
        let r = pl011_at(base);
        r.cr.write(0);                      // disable UART
        r.ibrd.write(13);                   // 115200 @ 24 MHz
        r.fbrd.write(1);
        r.lcr_h.write((3 << 5) | (1 << 4)); // 8N1, FIFO on
        r.cr.write(CR_UARTEN | CR_TXE | CR_RXE);
    }

    pub unsafe fn init() {
        unsafe {
            let fdt = fdt::info();

            // Prefer PL011 if FDT found one (QEMU path)
            if fdt.uart_base != 0 {
                pl011_init(fdt.uart_base);
                BACKEND.init(SerialBackend::Pl011 { base: fdt.uart_base });
                return;
            }

            // Try virtio-mmio console if FDT found virtio-mmio devices
            if fdt.virtio_count > 0 {
                for i in 0..fdt.virtio_count as usize {
                    if virtio_console_init_mmio(fdt.virtio_bases[i]) {
                        BACKEND.init(SerialBackend::Virtio);
                        return;
                    }
                }
            }

            // PCI VirtIO console (PCI-based platforms)
            if fdt.pcie_ecam_base != 0 {
                pci_init();
                if virtio_console_init_pci() {
                    BACKEND.init(SerialBackend::Virtio);
                    return;
                }
            }

            // No console found — putc() is a no-op, kernel runs silently.
        }
    }

    pub unsafe fn putc(c: u8) {
        match BACKEND.try_get() {
            Some(SerialBackend::Virtio) => unsafe { virtio_console_putc(c) },
            Some(SerialBackend::Pl011 { base }) => {
                let r = pl011_at(*base);
                // Wait for TX FIFO not full
                while (r.fr.read() & FR_TXFF) != 0 {}
                r.dr.write(c as u32);
            }
            None => {}
        }
    }

    pub unsafe fn try_getc() -> i32 {
        match BACKEND.try_get() {
            Some(SerialBackend::Virtio) => unsafe { virtio_console_try_getc() },
            Some(SerialBackend::Pl011 { base }) => {
                let r = pl011_at(*base);
                if (r.fr.read() & FR_RXFE) == 0 {
                    (r.dr.read() & 0xFF) as i32
                } else {
                    -1
                }
            }
            None => -1,
        }
    }
}

// ============================================================================
// Common serial API
// ============================================================================

static SHUTDOWN_REQUESTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Serial-write spinlock. Serialises whole `puts`/`putc` calls so
/// multi-core log output isn't interleaved or torn (the underlying
/// COM1/PL011 ports take a single byte per cycle, but the VirtIO
/// console backend has a shared TX descriptor ring that races if two
/// cores write concurrently).
///
/// Wraps `()` because we don't need to protect any inner data — the
/// underlying serial state is owned by the device-specific putc/puts
/// implementations. The lock just provides mutual exclusion.
static SERIAL_TX_LOCK: crate::sync::Spinlock<()> = crate::sync::Spinlock::new(());

pub fn init() {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        x86::init();
        #[cfg(target_arch = "aarch64")]
        aarch64::init();
    }
}

pub fn putc(c: u8) {
    let _guard = SERIAL_TX_LOCK.lock();
    unsafe {
        #[cfg(target_arch = "x86_64")]
        x86::putc(c);
        #[cfg(target_arch = "aarch64")]
        aarch64::putc(c);
    }
    // _guard released at end of scope.
}

pub fn puts(s: &[u8]) {
    // Take the lock once around the whole string so multi-core log
    // lines don't interleave at byte granularity. RAII releases on
    // scope exit.
    let _guard = SERIAL_TX_LOCK.lock();
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

/// Serial writer for use with core::fmt::Write. Used internally by
/// `serial::write_fmt` while SERIAL_TX_LOCK is held — emits bytes
/// directly via the arch-specific UART helpers without re-acquiring
/// the lock. Do NOT call this from anywhere that doesn't already
/// hold the lock; that's why it's private.
struct LockedWriter;

impl core::fmt::Write for LockedWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            unsafe {
                if b == b'\n' {
                    #[cfg(target_arch = "x86_64")] x86::putc(b'\r');
                    #[cfg(target_arch = "aarch64")] aarch64::putc(b'\r');
                }
                #[cfg(target_arch = "x86_64")] x86::putc(b);
                #[cfg(target_arch = "aarch64")] aarch64::putc(b);
            }
        }
        Ok(())
    }
}

/// Formatted serial output from Rust code. Hold SERIAL_TX_LOCK once
/// around the whole format operation so multi-chunk format machinery
/// (which calls `write_str` once per literal/argument segment) can't
/// be interleaved by another core's serial output. Without this, two
/// concurrent klog!s line-mangle into things like
/// `[net] Tier 1: per-core RX queues ([BOOT] En8 queue pairs)`.
pub fn write_fmt(args: core::fmt::Arguments) {
    use core::fmt::Write;
    let _guard = SERIAL_TX_LOCK.lock();
    let _ = LockedWriter.write_fmt(args);
}
