// tools/hvf-runner/src/pl011.rs
//
// PL011 UART emulation. Only the registers the kernel actually touches
// are implemented; everything else is RAZ/WI (read-as-zero, write-ignore).
//
// The kernel's PL011 driver (kernel/serial.rs) uses:
//   DR   (0x000) — data register: write = TX byte, read = RX byte
//   FR   (0x018) — flag register: bit 5 = TXFF, bit 4 = RXFE
//   IBRD (0x024) — integer baud rate divisor (write, ignored by us)
//   FBRD (0x028) — fractional baud rate divisor (write, ignored)
//   LCR_H(0x02C) — line control (write, ignored)
//   CR   (0x030) — control register (write, ignored — we're always "on")

use std::collections::VecDeque;
use std::io::Write;
use std::sync::Mutex;

/// Shared RX buffer. Stdin reader thread pushes bytes; the vCPU thread's
/// MMIO handler pops them on DR reads.
pub static RX_BUF: Mutex<VecDeque<u8>> = Mutex::new(VecDeque::new());

/// True if the guest's pl011 has at least one byte waiting to be read.
/// Used by the vm cooperative-yield loop to break out of a parked vCPU
/// so that Ctrl-C (forwarded as a raw 0x03 byte via `enable_raw`) can
/// reach the guest's serial RX path for graceful shutdown.
pub fn rx_has_data() -> bool {
    !RX_BUF.lock().unwrap().is_empty()
}

/// PL011 register offsets (from ARM PrimeCell PL011 r1p5 TRM).
const DR: u64 = 0x000;
const FR: u64 = 0x018;

/// Flag register bits. We always emulate the TX FIFO as empty (writes
/// always succeed on the host stdio sink), so FR_TXFF isn't read — but
/// it's part of the register layout the kernel may inspect, and
/// documenting the full shape of FR here is more helpful than pretending
/// the bit doesn't exist.
#[allow(dead_code)]
const FR_TXFF: u32 = 1 << 5; // TX FIFO full
const FR_RXFE: u32 = 1 << 4; // RX FIFO empty

/// Handle a guest MMIO read from the PL011 region.
pub fn mmio_read(offset: u64, _size: u8) -> u64 {
    match offset {
        DR => {
            // Pop one byte from the RX buffer, or 0 if empty.
            RX_BUF
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(0) as u64
        }
        FR => {
            // TX is never full (we flush synchronously to stdout).
            // RX is empty if the stdin buffer has nothing.
            let rxfe = if RX_BUF.lock().unwrap().is_empty() {
                FR_RXFE
            } else {
                0
            };
            rxfe as u64
        }
        // All other registers: read-as-zero.
        _ => 0,
    }
}

/// Handle a guest MMIO write to the PL011 region.
///
/// `size` is the access width in bytes (1, 2, 4, or 8) from the
/// instruction's encoding. We extend the PL011 spec by treating a
/// multi-byte write to DR as a packed batch — all `size` low bytes
/// of `value` are emitted in order. This is non-standard (the PL011
/// TRM defines DR as a 12-bit register), but it lets the guest
/// emit up to 8 chars per vmexit instead of one. On HVF where every
/// MMIO is a vmexit (~20 µs), the speedup is real (~5 ms boot →
/// ~1 ms boot for log-heavy startup). QEMU's PL011 emulation is
/// byte-only so the guest stays per-byte there.
pub fn mmio_write(offset: u64, size: u8, value: u64) {
    match offset {
        DR => {
            // Buffer output and flush on newline or when the buffer
            // gets large, to avoid one syscall per character.
            //
            // We use a thread-local buffer because the vCPU thread is
            // the only writer and we don't want to lock on every byte.
            thread_local! {
                static BUF: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
            }
            BUF.with(|buf| {
                let mut buf = buf.borrow_mut();
                let n = size.clamp(1, 8) as usize;
                let mut flush = false;
                for i in 0..n {
                    let byte = (value >> (i * 8)) as u8;
                    if byte == 0 { break; } // null-terminator early stop
                    buf.push(byte);
                    if byte == b'\n' { flush = true; }
                }
                if flush || buf.len() >= 256 {
                    let _ = std::io::stdout().write_all(&buf);
                    let _ = std::io::stdout().flush();
                    buf.clear();
                }
            });
        }
        // IBRD, FBRD, LCR_H, CR, etc. — all writes ignored.
        _ => {}
    }
}
