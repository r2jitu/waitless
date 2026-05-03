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
    use core::sync::atomic::{AtomicBool, Ordering};

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

    /// Two-stage console: 16550 (port-IO) is used for early boot
    /// before `pci::init` runs, then we try to upgrade to
    /// virtio-console-pci which batches output (one vmexit per
    /// ≤256-byte chunk vs one per byte for 16550). The early-stage
    /// 16550 path stays available as a fallback if QEMU's command
    /// line doesn't expose a virtio-serial-pci device.
    static USE_VIRTIO_CONSOLE: AtomicBool = AtomicBool::new(false);

    unsafe extern "C" {
        fn virtio_console_init_pci() -> bool;
        fn virtio_console_puts(ptr: *const u8, len: usize);
    }

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

    /// Probe for virtio-console-pci. Caller must run this AFTER
    /// `pci::init()` has scanned the PCI bus. On success, all
    /// subsequent `puts_raw` calls switch to the batched path —
    /// boot lines emitted before this point stay on the 16550
    /// stream so `-serial`-driven log capture still sees them.
    pub fn upgrade_to_virtio_console() {
        if unsafe { virtio_console_init_pci() } {
            USE_VIRTIO_CONSOLE.store(true, Ordering::Release);
        }
    }

    /// Emit `len` bytes to the active backend. One vmexit per
    /// ≤256-byte chunk on virtio-console-pci; one per byte on
    /// 16550 (early-boot fallback). Caller holds SERIAL_TX_LOCK.
    pub unsafe fn puts_raw(ptr: *const u8, len: usize) {
        if USE_VIRTIO_CONSOLE.load(Ordering::Acquire) {
            unsafe { virtio_console_puts(ptr, len); }
            return;
        }
        // 16550 fallback: per-byte port I/O. No LSR-empty poll —
        // every emulated 16550 path drains THR synchronously.
        let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
        for &b in bytes {
            unsafe { outb(COM1 + THR, b); }
        }
    }

    pub unsafe fn try_getc() -> i32 {
        if USE_VIRTIO_CONSOLE.load(Ordering::Acquire) {
            unsafe extern "C" { fn virtio_console_try_getc() -> i32; }
            return unsafe { virtio_console_try_getc() };
        }
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
            // Enable ERBFI (Received Data Available Interrupt).
            // Only meaningful when the 16550 backend is in use;
            // virtio-console RX is polled from `try_getc`.
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

    const FR_RXFE: u32 = 1 << 4; // RX FIFO empty
    const CR_UARTEN: u32 = 1 << 0;
    const CR_TXE: u32 = 1 << 8;
    const CR_RXE: u32 = 1 << 9;

    /// Discovered console backend. Set exactly once by `init()` on the
    /// BSP after FDT discovery, then read by every core. `InitOnce`
    /// gives us release/acquire publication and proper enum dispatch
    /// without magic-number constants.
    enum SerialBackend {
        /// QEMU TCG aarch64's `-machine virt` advertises a PL011 in
        /// the FDT and emulates it byte-by-byte. The HVF runner used
        /// to expose PL011 too (with a non-standard 8-byte-per-write
        /// fast path) but has migrated to virtio-console; this branch
        /// is now QEMU-only.
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
        fn virtio_console_puts(ptr: *const u8, len: usize);
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

            // Prefer PL011 if FDT found one (QEMU TCG aarch64 path —
            // its `-machine virt` always advertises one).
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

    /// Emit a slice on the discovered backend. Caller must hold
    /// SERIAL_TX_LOCK.
    pub unsafe fn puts_raw(bytes: &[u8]) {
        match BACKEND.try_get() {
            Some(SerialBackend::Virtio) => {
                unsafe { virtio_console_puts(bytes.as_ptr(), bytes.len()); }
            }
            Some(SerialBackend::Pl011 { base }) => {
                let r = pl011_at(*base);
                for &b in bytes { r.dr.write(b as u32); }
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

/// `true` when the next emitted byte is the first byte of a new
/// line. Used to drive the "[N.NNN] " timestamp prefix that every
/// serial line gets — same Linux-`dmesg` shape, ms-precision.
/// Mutated only under SERIAL_TX_LOCK.
static AT_LINE_START: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(true);

/// Stack-buffered writer used by `puts` and `LockedWriter::write_str`.
/// Appends bytes with `\r\n` + timestamp-prefix handling into a
/// fixed-size buffer; flushes via the arch-specific `puts_raw` (which
/// on HVF emits up to 8 bytes per vmexit) when full or when the
/// caller drops the writer. Caller MUST hold SERIAL_TX_LOCK.
const SERIAL_BUF_SIZE: usize = 256;

struct LineBuf {
    buf: [u8; SERIAL_BUF_SIZE],
    pos: usize,
}

impl LineBuf {
    fn new() -> Self {
        Self { buf: [0u8; SERIAL_BUF_SIZE], pos: 0 }
    }

    fn append(&mut self, b: u8) {
        // Reserve 16 bytes so a `\r\n` + worst-case timestamp prefix
        // (`[NNNNN.NNN] ` = 12 chars) fits without splitting.
        if self.pos >= SERIAL_BUF_SIZE - 16 {
            self.flush();
        }
        self.buf[self.pos] = b;
        self.pos += 1;
    }

    fn append_timestamp_if_line_start(&mut self) {
        use core::sync::atomic::Ordering;
        if !AT_LINE_START.load(Ordering::Relaxed) {
            return;
        }
        AT_LINE_START.store(false, Ordering::Relaxed);
        // Microsecond resolution: HVF boot is ~1 ms total now, so
        // millisecond-only timestamps lump the entire boot into a
        // single tick. Format `[S.uuuuuu]` (seconds + 6 µs digits).
        let us = crate::time::since_boot_us();
        let secs = us / 1_000_000;
        let us_part = (us % 1_000_000) as u32;
        self.append(b'[');
        if secs == 0 {
            self.append(b'0');
        } else {
            let mut tmp = [0u8; 10];
            let mut len = 0;
            let mut s = secs;
            while s > 0 { tmp[len] = b'0' + (s % 10) as u8; s /= 10; len += 1; }
            for i in 0..len { self.append(tmp[len - 1 - i]); }
        }
        self.append(b'.');
        self.append(b'0' + (us_part / 100_000) as u8);
        self.append(b'0' + ((us_part / 10_000) % 10) as u8);
        self.append(b'0' + ((us_part / 1_000) % 10) as u8);
        self.append(b'0' + ((us_part / 100) % 10) as u8);
        self.append(b'0' + ((us_part / 10) % 10) as u8);
        self.append(b'0' + (us_part % 10) as u8);
        self.append(b']');
        self.append(b' ');
    }

    fn write_byte(&mut self, b: u8) {
        self.append_timestamp_if_line_start();
        if b == b'\n' {
            self.append(b'\r');
            self.append(b'\n');
            AT_LINE_START.store(true, core::sync::atomic::Ordering::Relaxed);
        } else {
            self.append(b);
        }
    }

    fn flush(&mut self) {
        if self.pos == 0 { return; }
        // SAFETY: caller holds SERIAL_TX_LOCK; `puts_raw` is the
        // arch-specific batched-write path (multi-byte MMIO on HVF,
        // per-byte fallback on QEMU PL011 / x86 16550).
        unsafe { arch_puts_raw(&self.buf[..self.pos]); }
        self.pos = 0;
    }
}

impl Drop for LineBuf {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Arch-specific batched write. Caller holds SERIAL_TX_LOCK.
#[inline]
unsafe fn arch_puts_raw(bytes: &[u8]) {
    #[cfg(target_arch = "aarch64")]
    unsafe { aarch64::puts_raw(bytes); }
    #[cfg(target_arch = "x86_64")]
    unsafe { x86::puts_raw(bytes.as_ptr(), bytes.len()); }
}

pub fn init() {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        x86::init();
        #[cfg(target_arch = "aarch64")]
        aarch64::init();
    }
}

/// Try to upgrade the early-boot console to virtio-console-pci.
/// Caller must run this AFTER `uni_drivers::pci::init()` has
/// populated the PCI device table.
///
/// On x86 the early-boot console is the 16550 UART (port-IO,
/// 1 vmexit per byte). Once virtio-serial-pci is reachable —
/// QEMU/KVM with `-device virtio-serial-pci -device virtconsole`
/// — switching to the virtio-console backend cuts log-line
/// emission to 1 vmexit per ≤256-byte chunk. Boot is faster
/// (fewer per-line vmexits during the listener-init phase) and
/// runtime gets the same benefit for any post-boot output.
///
/// On aarch64 the existing `aarch64::init` already picks the
/// best backend from the FDT (PL011 / virtio-mmio /
/// virtio-pci-console), so this is a no-op.
pub fn upgrade_after_pci() {
    #[cfg(target_arch = "x86_64")]
    x86::upgrade_to_virtio_console();
}

pub fn putc(c: u8) {
    let _guard = SERIAL_TX_LOCK.lock();
    let mut lb = LineBuf::new();
    lb.write_byte(c);
}

pub fn puts(s: &[u8]) {
    // Take the lock once around the whole string so multi-core log
    // lines don't interleave at byte granularity. RAII releases on
    // scope exit; `LineBuf::Drop` flushes any tail bytes.
    let _guard = SERIAL_TX_LOCK.lock();
    let mut lb = LineBuf::new();
    for &c in s {
        lb.write_byte(c);
    }
}

/// Print a u64 as 0x-prefixed lowercase hex. Used by panic/exception
/// handlers where formatting via core::fmt would be risky (e.g. from
/// within an ISR). Takes the same serial lock as `puts`.
pub fn print_hex(v: u64) {
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        let nib = ((v >> (60 - i * 4)) & 0xf) as u8;
        buf[2 + i] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
    }
    puts(&buf);
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
struct LockedWriter {
    lb: LineBuf,
}

impl LockedWriter {
    fn new() -> Self {
        Self { lb: LineBuf::new() }
    }
}

impl core::fmt::Write for LockedWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            self.lb.write_byte(b);
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
    let mut w = LockedWriter::new();
    let _ = w.write_fmt(args);
    // `w.lb` flushes on drop at end of scope.
}
