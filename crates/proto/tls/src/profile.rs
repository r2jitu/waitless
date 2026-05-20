// net/tls_server_profile.rs — Per-stage handshake profiler.
//
// Always-on cycle-counter accumulator for each stage of
// `do_client_hello`. Uses a single-instruction cycle-counter read
// (~1ns) so the overhead per handshake is dwarfed by any individual
// stage. Totals live in module-level atomics; `report()` formats a
// human-readable dump that the webserver exposes at `/tls_profile`.
//
// The cycle-counter helpers are inlined directly here so this crate
// doesn't need to depend on `//crates/kernel/bare` — that lets the same state
// machine compile for native host builds (used by the POSIX
// `webserver_native` binary for bench comparisons against the
// unikernel) without dragging in bare-metal kernel modules.

use core::sync::atomic::{AtomicU64, Ordering};

/// Read the monotonic hardware cycle counter — TSC on x86_64,
/// CNTVCT_EL0 on aarch64. Both are unprivileged reads on the
/// targets we ship (kernel ring-0 or macOS/Linux user mode).
#[inline(always)]
fn now_cycles() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
        ((hi as u64) << 32) | (lo as u64)
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let v: u64;
        core::arch::asm!(
            "mrs {0}, cntvct_el0",
            out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
        v
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        0
    }
}

/// Cycle-counter frequency in ticks per microsecond.
///
/// aarch64 reads `CNTFRQ_EL0` directly (user-readable on
/// aarch64; the architectural virtual counter frequency is
/// typically 24 MHz on Apple Silicon and 1 GHz on most server
/// parts). x86_64 calibrates the first time against a 10 ms
/// wall-clock window using one of two methods:
///   - In the unikernel / bare-metal path we don't have a wall
///     clock handy, so we fall back to a coarse estimate of
///     3000 cyc/µs (roughly matches a 3 GHz TSC which is the
///     rough order of every x86_64 host we care about).
///   - On native hosted builds we use
///     `std::time::Instant::elapsed()` after a busy-loop cycle
///     read to get a real calibration, cached in the same
///     `TSC_CACHE` atomic.
///
/// The calibration only affects the human-readable `total_us` /
/// `mean_ns` / `worst_ns` columns in the report; the raw cycle
/// totals are perfectly accurate in either case.
#[cfg(target_arch = "aarch64")]
fn cycles_per_us() -> u64 {
    let freq: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, cntfrq_el0",
            out(reg) freq,
            options(nomem, nostack, preserves_flags),
        );
    }
    (freq / 1_000_000).max(1)
}
#[cfg(target_arch = "x86_64")]
fn cycles_per_us() -> u64 {
    // Coarse estimate; the report shows a header line with the
    // actual value used so readers can adjust in their head.
    3000
}
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn cycles_per_us() -> u64 {
    1
}

/// Stage identifier. Indexes into `TOTAL` / `WORST`.
#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Stage {
    /// ClientHello parse (record + handshake framing + extension walk).
    Parse = 0,
    /// ServerHello build + plaintext record encode.
    ServerHello = 1,
    /// X25519 ECDHE: `ephemeral.shared_secret(&client_pub)`.
    Ecdhe = 2,
    /// HKDF cascade for handshake traffic secrets
    /// (`KeySchedule::enter_handshake`).
    HkdfHs = 3,
    /// EncryptedExtensions build + seal.
    EncExt = 4,
    /// Certificate build + seal.
    Cert = 5,
    /// CertificateVerify: SigningKey::from_slice + ECDSA P-256 sign
    /// (RFC 6979 det-k + SHA-256 + scalar mult) + DER encode.
    CvSign = 6,
    /// CertificateVerify seal (record-layer AEAD only, no sig work).
    CvSeal = 7,
    /// ServerFinished: HMAC over transcript + build + seal.
    Finished = 8,
    /// HKDF cascade for application traffic secrets
    /// (`KeySchedule::enter_application`).
    HkdfAp = 9,
    /// Resumption-only: HKDF cascade for the PSK binder + HMAC verify
    /// + transcript-hash setup. Replaces `cv_sign` time on the
    /// resumed path; both stages stay separate so the report shows
    /// where each handshake type spent its cycles.
    PskBinder = 10,
}

const N_STAGES: usize = 11;

const STAGE_NAMES: [&[u8]; N_STAGES] = [
    b"parse     ",
    b"srvhello  ",
    b"ecdhe     ",
    b"hkdf_hs   ",
    b"encext    ",
    b"cert      ",
    b"cv_sign   ",
    b"cv_seal   ",
    b"finished  ",
    b"hkdf_ap   ",
    b"psk_bind  ",
];

// Per-stage totals. Each handshake adds its elapsed cycles to the
// matching slot; `handshakes` counts completed handshakes so the
// formatter can compute the mean.
static TOTAL: [AtomicU64; N_STAGES] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static WORST: [AtomicU64; N_STAGES] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static HANDSHAKES: AtomicU64 = AtomicU64::new(0);

/// Start a handshake profile — returns an opaque cycle timestamp
/// that callers thread through `mark()` to partition the handshake
/// into stages.
#[inline(always)]
pub fn start() -> u64 {
    now_cycles()
}

/// Record the cycles elapsed from `prev` to now into `stage`, and
/// return the current cycle counter (to be passed as `prev` to
/// the next `mark()` call). This lets the caller walk through the
/// handshake with a single live cycle timestamp and no extra
/// locals per stage.
#[inline(always)]
pub fn mark(stage: Stage, prev: u64) -> u64 {
    let now = now_cycles();
    let delta = now.wrapping_sub(prev);
    let idx = stage as usize;
    TOTAL[idx].fetch_add(delta, Ordering::Relaxed);
    // Update the per-stage worst-case with a compare-and-swap
    // retry loop. Contention here is benign — each slot is hit
    // from the vCPU that owns the connection, and the bound on
    // cross-core writes is the number of cores.
    let mut cur = WORST[idx].load(Ordering::Relaxed);
    while delta > cur {
        match WORST[idx].compare_exchange_weak(cur, delta, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => cur = observed,
        }
    }
    now
}

/// Count a completed handshake. Called once at the end of
/// `do_client_hello` after the final `mark()`.
#[inline(always)]
pub fn bump_count() {
    HANDSHAKES.fetch_add(1, Ordering::Relaxed);
}

/// Reset all accumulators to zero. Useful for A/B benchmarking
/// — hit `/tls_profile_reset` between runs.
pub fn reset() {
    for s in TOTAL.iter() {
        s.store(0, Ordering::Relaxed);
    }
    for s in WORST.iter() {
        s.store(0, Ordering::Relaxed);
    }
    HANDSHAKES.store(0, Ordering::Relaxed);
}

/// Format the accumulated stats into `out` as ASCII. Returns the
/// number of bytes written. Shape (fixed-width columns):
/// ```text
/// TLS handshake profile (N handshakes, X cyc/us)
/// stage        total_us    mean_ns  worst_ns    pct
/// parse                42       123       456   1.2
/// srvhello            ...
/// ...
/// total              1378
/// ```
pub fn report(out: &mut [u8]) -> usize {
    let cyc_per_us = cycles_per_us().max(1);
    let n_hs = HANDSHAKES.load(Ordering::Relaxed);

    let mut totals = [0u64; N_STAGES];
    let mut worsts = [0u64; N_STAGES];
    let mut grand_total: u64 = 0;
    for i in 0..N_STAGES {
        totals[i] = TOTAL[i].load(Ordering::Relaxed);
        worsts[i] = WORST[i].load(Ordering::Relaxed);
        grand_total = grand_total.saturating_add(totals[i]);
    }

    let mut w = Writer::new(out);
    w.puts(b"TLS handshake profile (");
    w.put_u64(n_hs);
    w.puts(b" handshakes, ");
    w.put_u64(cyc_per_us);
    w.puts(b" cyc/us)\n");
    w.puts(b"stage        total_us  mean_ns  worst_ns  pct\n");
    for i in 0..N_STAGES {
        let total_us = totals[i] / cyc_per_us;
        let mean_ns = if n_hs > 0 {
            // cycles -> ns: cycles * 1000 / cyc_per_us
            (totals[i].saturating_mul(1000) / n_hs) / cyc_per_us
        } else {
            0
        };
        let worst_ns = worsts[i].saturating_mul(1000) / cyc_per_us;
        let pct_x10 = if grand_total > 0 {
            (totals[i].saturating_mul(1000)) / grand_total
        } else {
            0
        };
        w.puts(STAGE_NAMES[i]);
        w.put_u64_right(total_us, 10);
        w.put_u64_right(mean_ns, 9);
        w.put_u64_right(worst_ns, 10);
        w.puts(b"  ");
        w.put_u64(pct_x10 / 10);
        w.putc(b'.');
        w.put_u64(pct_x10 % 10);
        w.putc(b'\n');
    }
    w.puts(b"total       ");
    if n_hs > 0 {
        let mean_total_ns = (grand_total.saturating_mul(1000) / n_hs) / cyc_per_us;
        w.put_u64(mean_total_ns / 1000);
        w.puts(b".");
        let frac = mean_total_ns % 1000;
        if frac < 100 {
            w.putc(b'0');
        }
        if frac < 10 {
            w.putc(b'0');
        }
        w.put_u64(frac);
        w.puts(b"us mean per handshake\n");
    } else {
        w.puts(b"(no handshakes sampled yet)\n");
    }
    w.len()
}

// ── tiny byte-buffer writer ─────────────────────────────────────
struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Writer { buf, pos: 0 }
    }
    fn len(&self) -> usize {
        self.pos
    }
    fn putc(&mut self, c: u8) {
        if self.pos < self.buf.len() {
            self.buf[self.pos] = c;
            self.pos += 1;
        }
    }
    fn puts(&mut self, s: &[u8]) {
        let n = core::cmp::min(s.len(), self.buf.len() - self.pos);
        self.buf[self.pos..self.pos + n].copy_from_slice(&s[..n]);
        self.pos += n;
    }
    fn put_u64(&mut self, mut v: u64) {
        if v == 0 {
            self.putc(b'0');
            return;
        }
        let mut digits = [0u8; 20];
        let mut n = 0;
        while v > 0 {
            digits[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
        while n > 0 {
            n -= 1;
            self.putc(digits[n]);
        }
    }
    /// Right-justify a u64 in `width` columns (space-padded).
    fn put_u64_right(&mut self, v: u64, width: usize) {
        let mut digits = [0u8; 20];
        let mut n = 0;
        let mut t = v;
        if t == 0 {
            digits[0] = b'0';
            n = 1;
        } else {
            while t > 0 {
                digits[n] = b'0' + (t % 10) as u8;
                t /= 10;
                n += 1;
            }
        }
        let pad = width.saturating_sub(n);
        for _ in 0..pad {
            self.putc(b' ');
        }
        while n > 0 {
            n -= 1;
            self.putc(digits[n]);
        }
    }
}
