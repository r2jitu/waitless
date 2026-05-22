// kernel/diag.rs — In-band diagnostic capture for panics + unhandled exceptions.
//
// Production deployments on GCE run with serial-port-output access locked
// down (sandbox / IAM), so a panic that fires there is invisible from the
// outside. This module captures the same bytes our `panic_handler` and
// `isr_common_handler` would write to serial into a static in-memory ring,
// so the webserver can expose them via `/diag-panic`.
//
// Design constraints:
//
//   * **Allocation-free** — usable from inside the panic handler itself,
//     where the heap may be wedged or the global allocator unsafe to call.
//   * **Multi-core safe** — any worker can panic, and we want their
//     records to land without corrupting each other. A short Spinlock
//     around the small static buffer is fine: the write path runs once
//     per panic / exception, the read path runs once per `/diag-panic`
//     request.
//   * **Survives the panicking core** — once a core enters `panic` or
//     `isr_common_handler` for an unhandled exception, it halts. Other
//     cores keep running and can read this buffer. So the buffer lives
//     in a static, not in `PerCore`.
//   * **Bounded** — 4 KiB total, FIFO-truncate when full. Multi-record
//     captures (e.g. one core panics, then another) accumulate up to
//     the cap; further writes are silently dropped.

use sync::Spinlock;

/// Total bytes of capture. 4 KiB is plenty for a few panic records
/// (a single panic record is ~200-400 B with all the context).
pub const CAPTURE_LEN: usize = 4096;

struct Capture {
    bytes: [u8; CAPTURE_LEN],
    /// Bytes written so far (≤ CAPTURE_LEN). Once this hits the cap
    /// further `append`s no-op — we'd rather keep the first record's
    /// context than overwrite it with later noise.
    len: usize,
}

impl Capture {
    const EMPTY: Self = Capture {
        bytes: [0; CAPTURE_LEN],
        len: 0,
    };

    fn append(&mut self, src: &[u8]) {
        let space = CAPTURE_LEN.saturating_sub(self.len);
        let n = src.len().min(space);
        self.bytes[self.len..self.len + n].copy_from_slice(&src[..n]);
        self.len += n;
    }
}

static CAPTURE: Spinlock<Capture> = Spinlock::new(Capture::EMPTY);

/// Append `bytes` to the in-memory capture buffer. Safe to call from
/// any context (panic handler, IRQ handler, normal code). FIFO-bounded
/// at `CAPTURE_LEN`.
pub fn append(bytes: &[u8]) {
    CAPTURE.lock().append(bytes);
}

/// Append a hex u64 (without the `0x` prefix) — convenient for
/// formatting RIP / error_code / CR2 from raw values without
/// pulling in `core::fmt`.
pub fn append_hex(value: u64) {
    let mut buf = [0u8; 16];
    for (i, b) in buf.iter_mut().enumerate() {
        let nibble = ((value >> ((15 - i) * 4)) & 0xF) as u8;
        *b = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
    }
    append(&buf);
}

/// Append a 2-char hex byte (without the `0x` prefix). Used by
/// boot-time KAT dumps that need readable byte-windows in the
/// `/diag-panic` output, where `append_hex(b as u64)` would render
/// as 16 leading zeros + 2 useful chars.
pub fn append_hex_u8(value: u8) {
    let hi = value >> 4;
    let lo = value & 0xF;
    let buf = [
        if hi < 10 { b'0' + hi } else { b'a' + (hi - 10) },
        if lo < 10 { b'0' + lo } else { b'a' + (lo - 10) },
    ];
    append(&buf);
}

/// Append a decimal u32 — used for cpu IDs and small counters.
pub fn append_u32(value: u32) {
    if value == 0 {
        append(b"0");
        return;
    }
    // Largest u32 = 4_294_967_295 → 10 digits.
    let mut buf = [0u8; 10];
    let mut v = value;
    let mut i = 10;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    append(&buf[i..]);
}

/// Snapshot the current capture into `out`. Returns the number of bytes
/// written. Read-side path — locks the same Spinlock as `append`, so an
/// active panic will block this momentarily but not for long (the
/// panicking core finishes its `append`s within a few microseconds and
/// then halts, releasing the lock).
pub fn snapshot(out: &mut [u8]) -> usize {
    let cap = CAPTURE.lock();
    let n = cap.len.min(out.len());
    out[..n].copy_from_slice(&cap.bytes[..n]);
    n
}

/// Total bytes captured so far. Cheap read-only check, useful for the
/// `/diag-panic` endpoint to short-circuit when nothing's been
/// captured yet.
pub fn captured_len() -> usize {
    CAPTURE.lock().len
}

/// Reset the capture to empty. Lets a debugger trigger a deliberate
/// panic, read it via `/diag-panic`, and then clear the buffer for
/// the next iteration without rebooting.
pub fn reset() {
    let mut cap = CAPTURE.lock();
    cap.len = 0;
}
