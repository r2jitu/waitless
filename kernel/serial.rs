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
// Rust output. C++ callers use serial_putc/serial_puts via thin wrappers
// in serial.h; serial::printf remains in C++ (serial_printf.cc) until all
// C++ callers are migrated.

#![no_std]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(static_mut_refs)]

use core::ptr;

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
        asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
    }

    #[inline(always)]
    unsafe fn inb(port: u16) -> u8 {
        let ret: u8;
        asm!("in al, dx", out("al") ret, in("dx") port, options(nomem, nostack));
        ret
    }

    pub unsafe fn init() {
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

    pub unsafe fn putc(c: u8) {
        // Wait for THR empty (LSR bit 5)
        while (inb(COM1 + LSR) & 0x20) == 0 {}
        outb(COM1 + THR, c);
    }

    pub unsafe fn try_getc() -> i32 {
        // LSR bit 0 = Data Ready
        if (inb(COM1 + LSR) & 0x01) != 0 {
            inb(COM1 + RBR) as i32
        } else {
            -1
        }
    }

    pub unsafe fn enable_rx_irq() {
        // Enable ERBFI (Received Data Available Interrupt)
        outb(COM1 + IER, 0x01);
    }
}

// ============================================================================
// aarch64: PL011 UART + VirtIO console backends
// ============================================================================

#[cfg(target_arch = "aarch64")]
mod aarch64 {
    use core::ptr;

    // PL011 register offsets
    const PL011_DR: u64 = 0x000;    // Data register
    const PL011_FR: u64 = 0x018;    // Flag register
    const PL011_IBRD: u64 = 0x024;  // Integer baud rate divisor
    const PL011_FBRD: u64 = 0x028;  // Fractional baud rate divisor
    const PL011_LCR_H: u64 = 0x02C; // Line control
    const PL011_CR: u64 = 0x030;    // Control

    const FR_TXFF: u32 = 1 << 5; // TX FIFO full
    const FR_RXFE: u32 = 1 << 4; // RX FIFO empty
    const CR_UARTEN: u32 = 1 << 0;
    const CR_TXE: u32 = 1 << 8;
    const CR_RXE: u32 = 1 << 9;

    #[derive(Clone, Copy, PartialEq)]
    enum Backend { None, Pl011, Virtio }

    static mut BACKEND: Backend = Backend::None;
    static mut UART_BASE: u64 = 0;

    // FDT info struct — must match drivers_ffi.cc DriverFdtInfo
    #[repr(C)]
    struct FdtInfo {
        uart_base: u64,
        virtio_bases: [u64; 32],
        virtio_irqs: [u32; 32],
        virtio_count: i32,
        gic_dist_base: u64,
        gic_redist_base: u64,
        gic_version: u8,
        pcie_ecam_base: u64,
        pcie_ecam_size: u64,
        ram_base: u64,
        ram_size: u64,
        pci_mmio32_base: u64,
        pci_mmio32_size: u64,
        pci_irqs: [u32; 8],
    }

    unsafe extern "C" {
        fn driver_get_fdt_info(out: *mut FdtInfo);
        fn driver_pci_init();
        fn driver_virtio_console_init_mmio(base_addr: u64) -> bool;
        fn driver_virtio_console_init_pci() -> bool;
        fn driver_virtio_console_putc(c: u8);
        fn driver_virtio_console_try_getc() -> i32;
    }

    #[inline(always)]
    unsafe fn pl011_read(off: u64) -> u32 {
        ptr::read_volatile((UART_BASE + off) as *const u32)
    }

    #[inline(always)]
    unsafe fn pl011_write(off: u64, val: u32) {
        ptr::write_volatile((UART_BASE + off) as *mut u32, val);
    }

    unsafe fn pl011_init(base: u64) {
        UART_BASE = base;
        pl011_write(PL011_CR, 0);           // disable UART
        pl011_write(PL011_IBRD, 13);        // 115200 @ 24 MHz
        pl011_write(PL011_FBRD, 1);
        pl011_write(PL011_LCR_H, (3 << 5) | (1 << 4)); // 8N1, FIFO on
        pl011_write(PL011_CR, CR_UARTEN | CR_TXE | CR_RXE);
        BACKEND = Backend::Pl011;
    }

    pub unsafe fn init() {
        let mut fdt = core::mem::MaybeUninit::<FdtInfo>::zeroed();
        driver_get_fdt_info(fdt.as_mut_ptr());
        let fdt = fdt.assume_init();

        // Prefer PL011 if FDT found one (QEMU path)
        if fdt.uart_base != 0 {
            pl011_init(fdt.uart_base);
            return;
        }

        // Try virtio-mmio console if FDT found virtio-mmio devices
        if fdt.virtio_count > 0 {
            for i in 0..fdt.virtio_count as usize {
                if driver_virtio_console_init_mmio(fdt.virtio_bases[i]) {
                    BACKEND = Backend::Virtio;
                    return;
                }
            }
        }

        // PCI VirtIO console (VZ.framework and other PCI platforms)
        if fdt.pcie_ecam_base != 0 {
            driver_pci_init();
            if driver_virtio_console_init_pci() {
                BACKEND = Backend::Virtio;
                return;
            }
        }

        // No console found — putc() is a no-op, kernel runs silently.
    }

    pub unsafe fn putc(c: u8) {
        match BACKEND {
            Backend::Virtio => driver_virtio_console_putc(c),
            Backend::None => {},
            Backend::Pl011 => {
                // Wait for TX FIFO not full
                while (pl011_read(PL011_FR) & FR_TXFF) != 0 {}
                pl011_write(PL011_DR, c as u32);
            }
        }
    }

    pub unsafe fn try_getc() -> i32 {
        match BACKEND {
            Backend::Virtio => driver_virtio_console_try_getc(),
            Backend::None => -1,
            Backend::Pl011 => {
                if (pl011_read(PL011_FR) & FR_RXFE) == 0 {
                    (pl011_read(PL011_DR) & 0xFF) as i32
                } else {
                    -1
                }
            }
        }
    }
}

// ============================================================================
// Common serial API — exported as extern "C" for C++ callers
// ============================================================================

static mut SHUTDOWN_REQUESTED: bool = false;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn serial_init() {
    #[cfg(target_arch = "x86_64")]
    x86::init();
    #[cfg(target_arch = "aarch64")]
    aarch64::init();
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn serial_putc(c: u8) {
    #[cfg(target_arch = "x86_64")]
    x86::putc(c);
    #[cfg(target_arch = "aarch64")]
    aarch64::putc(c);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn serial_puts(s: *const u8) {
    if s.is_null() {
        return;
    }
    let mut p = s;
    while unsafe { *p } != 0 {
        let c = unsafe { *p };
        if c == b'\n' {
            serial_putc(b'\r');
        }
        serial_putc(c);
        p = unsafe { p.add(1) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn serial_try_getc() -> i32 {
    #[cfg(target_arch = "x86_64")]
    { x86::try_getc() }
    #[cfg(target_arch = "aarch64")]
    { aarch64::try_getc() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn serial_check_shutdown() -> bool {
    if SHUTDOWN_REQUESTED {
        return true;
    }
    loop {
        let c = serial_try_getc();
        if c < 0 {
            break;
        }
        if c == 0x03 { // Ctrl-C
            SHUTDOWN_REQUESTED = true;
            return true;
        }
    }
    false
}

// x86_64-specific: RX interrupt support for idle wakeup on Ctrl-C
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn serial_enable_rx_irq() {
    x86::enable_rx_irq();
}

#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn serial_rx_isr() {
    // Drain RX FIFO to clear the UART interrupt condition
    loop {
        let c = x86::try_getc();
        if c < 0 {
            break;
        }
        if c == 0x03 {
            SHUTDOWN_REQUESTED = true;
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
                unsafe { serial_putc(b'\r') };
            }
            unsafe { serial_putc(b) };
        }
        Ok(())
    }
}

/// Formatted serial output from Rust code.
pub fn serial_write_fmt(args: core::fmt::Arguments) {
    use core::fmt::Write;
    let _ = SerialWriter.write_fmt(args);
}
