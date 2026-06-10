//! Entropy-source health tests + a min-entropy estimate for the kernel
//! RNG's jitter noise source (NIST SP 800-90B).
//!
//! `//crates/kernel/bare`'s `rng` seeds a SHA-256 hash-DRBG from a
//! cycle-counter "jitter" noise source. That construction is sound, but
//! it never *measured* the source — so we couldn't state how much
//! entropy the seed actually carried, and a stuck or badly-biased
//! counter (a pathological hypervisor TSC, say) would degrade silently.
//!
//! This module is the measurement half. It lives here (host-buildable
//! `kernel_core`) rather than in `//crates/kernel/bare` (os:none only)
//! so the arithmetic is unit-tested on the host; `rng` collects one
//! noise symbol per jitter read (the low byte of the inter-read
//! cycle-delta) and calls [`assess`] at seed time.
//!
//! What it implements:
//!   * **Repetition Count Test** (SP 800-90B §4.4.1) — the stuck-source
//!     detector: fail if one symbol repeats `RCT_CUTOFF` times in a row.
//!   * **Adaptive Proportion Test** (§4.4.2, practical variant) — a
//!     gross-bias detector over a window: fail if any symbol occupies
//!     more than a quarter of the window.
//!   * **Most-Common-Value min-entropy estimate** (§6.3.1) — the
//!     headline number: `H = −log2(p_upper)` where `p_upper` is the 99 %
//!     upper-confidence bound on the most frequent symbol's probability.
//!
//! The estimate is the standard MCV estimator; the two health tests use
//! the standard RCT cutoff and a deliberately-loose APT threshold (a
//! runtime smoke test, not a certified §4.4.2 cutoff — documented as
//! such so it never false-positives on a healthy source).

/// Repetition Count Test cutoff (SP 800-90B §4.4.1) for a design
/// min-entropy of 1 bit/symbol: `C = 1 + ceil(20 / H) = 21`. A run of
/// `RCT_CUTOFF` identical symbols means the source is stuck.
pub const RCT_CUTOFF: u32 = 21;

/// Adaptive Proportion Test window (SP 800-90B §4.4.2, non-binary).
pub const APT_WINDOW: usize = 512;

/// Verdict + estimate for one batch of noise symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HealthReport {
    /// Repetition Count Test passed (no stuck run ≥ `RCT_CUTOFF`).
    pub rct_pass: bool,
    /// Adaptive Proportion Test passed (no symbol dominated a window).
    pub apt_pass: bool,
    /// Most-common-value min-entropy estimate, in **milli-bits per
    /// symbol** (e.g. 7500 = 7.5 bits). Integer so it rides a `/obs`
    /// counter without a float. 0 for an empty input.
    pub min_entropy_mbits: u32,
    /// Number of symbols assessed.
    pub samples: u32,
}

impl HealthReport {
    /// `true` if both startup tests passed.
    pub fn healthy(&self) -> bool {
        self.rct_pass && self.apt_pass
    }
}

/// `round(1000 · log2(value))` where `value = y / 2^32` is a Q32
/// fixed-point number ≥ 1.0 (passed as a `u128` so callers needn't fear
/// overflow when `value` is large). Pure integer math — the kernel is
/// `no_std` with no `libm`, so `f64::log2` is unavailable. Iterative
/// bit-by-bit logarithm: integer part from the MSB position, fractional
/// part by repeated (rounded) squaring.
fn log2_q32_mbits(y: u128) -> u32 {
    debug_assert!(y >= (1u128 << 32), "value must be >= 1.0");
    // Integer part: msb index − 32.
    let msb = 127 - y.leading_zeros(); // 32..=127 for y >= 1<<32
    let int_part = msb - 32;
    // Normalize the mantissa into [1<<32, 2<<32) as a u64 Q32 value.
    let mut v: u64 = if msb >= 32 { (y >> (msb - 32)) as u64 } else { (y << (32 - msb)) as u64 };
    // Fractional part: accumulate 20 binary places into a Q20 fraction
    // of one bit (so resolution ≈ 0.001 milli-bit), converting to
    // milli-bits only at the end. Round (not truncate) each square so
    // the error doesn't bias the estimate downward.
    const FRAC_BITS: u32 = 20;
    let mut frac_q20: u64 = 0;
    for i in 0..FRAC_BITS {
        // Square the Q32 mantissa (rounded) → Q32 in [1<<32, 4<<32).
        v = (((v as u128) * (v as u128) + (1u128 << 31)) >> 32) as u64;
        if v >= (2u64 << 32) {
            frac_q20 |= 1 << (FRAC_BITS - 1 - i);
            v >>= 1; // renormalize into [1<<32, 2<<32)
        }
    }
    let frac_mbits = ((frac_q20 * 1000) >> FRAC_BITS) as u32;
    int_part * 1000 + frac_mbits
}

/// Most-Common-Value min-entropy estimate (SP 800-90B §6.3.1) in
/// milli-bits per symbol. `n` = sample count, `c_max` = the highest
/// symbol occurrence count. `H = −log2(p_upper)` with the 99 % upper
/// bound `p_upper = p̂ + 2.576·sqrt(p̂(1−p̂)/(n−1))`, `p̂ = c_max/n`.
fn mcv_min_entropy_mbits(n: u32, c_max: u32) -> u32 {
    if n == 0 || c_max == 0 {
        return 0;
    }
    if c_max >= n {
        return 0; // a single value → zero min-entropy.
    }
    // Work in Q32 fixed-point. p̂ = c_max / n.
    let nn = n as u64;
    let p_hat_q32 = ((c_max as u64) << 32) / nn;
    let one_q32: u64 = 1 << 32;
    // var = p̂(1−p̂)/(n−1), in Q32. p̂(1−p̂) ≤ 1/4 so the product fits.
    let q = one_q32 - p_hat_q32; // (1 − p̂) in Q32
    let prod_q32 = (((p_hat_q32 as u128) * (q as u128)) >> 32) as u64; // p̂(1−p̂) Q32
    let var_q32 = prod_q32 / (nn - 1);
    // sqrt(var) in Q32: isqrt(var_q32 << 32).
    let sd_q32 = isqrt_u128((var_q32 as u128) << 32) as u64;
    // p_upper = p̂ + 2.576·sd. 2.576 ≈ 2576/1000.
    let margin_q32 = (sd_q32 as u128 * 2576 / 1000) as u64;
    let p_upper_q32 = (p_hat_q32 + margin_q32).min(one_q32);
    if p_upper_q32 >= one_q32 {
        return 0;
    }
    // H = −log2(p_upper) = log2(1/p_upper). Form 1/p_upper as a Q32
    // value ≥ 1.0 in u128 (2^64 / p_upper_q32) so it can't overflow when
    // p_upper is small (high-entropy) — then take its log2.
    let inv_q32: u128 = (1u128 << 64) / (p_upper_q32 as u128);
    log2_q32_mbits(inv_q32)
}

/// Integer square root of a u128 (Newton's method). Used for the MCV
/// confidence-bound standard deviation.
fn isqrt_u128(v: u128) -> u128 {
    if v < 2 {
        return v;
    }
    let mut x = v;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + v / x) / 2;
    }
    x
}

/// Run the SP 800-90B startup health tests and the MCV min-entropy
/// estimate over `samples` (one noise symbol per byte).
pub fn assess(samples: &[u8]) -> HealthReport {
    let n = samples.len();
    if n == 0 {
        return HealthReport { rct_pass: true, apt_pass: true, min_entropy_mbits: 0, samples: 0 };
    }

    // Per-symbol histogram (256 buckets) — for both the APT and the MCV
    // estimate's most-frequent count.
    let mut hist = [0u32; 256];

    // Repetition Count Test: longest run of one value.
    let mut rct_pass = true;
    let mut run_val = samples[0];
    let mut run_len: u32 = 0;
    for &s in samples {
        hist[s as usize] += 1;
        if s == run_val {
            run_len += 1;
            if run_len >= RCT_CUTOFF {
                rct_pass = false;
            }
        } else {
            run_val = s;
            run_len = 1;
        }
    }

    // Adaptive Proportion Test (practical variant): over each
    // `APT_WINDOW`-symbol window, no single value may occupy more than a
    // quarter of the window. A healthy byte source spreads ~W/256 per
    // value, so this only trips on gross bias.
    let mut apt_pass = true;
    let apt_cutoff = (APT_WINDOW / 4) as u32;
    let mut w = 0;
    while w < n {
        let end = (w + APT_WINDOW).min(n);
        let mut wh = [0u32; 256];
        let mut worst = 0u32;
        for &s in &samples[w..end] {
            wh[s as usize] += 1;
            if wh[s as usize] > worst {
                worst = wh[s as usize];
            }
        }
        // Only judge full windows — a short tail window is not a valid
        // APT window and would false-positive on small batches.
        if end - w == APT_WINDOW && worst > apt_cutoff {
            apt_pass = false;
        }
        w = end;
    }

    let c_max = *hist.iter().max().unwrap_or(&0);
    let min_entropy_mbits = mcv_min_entropy_mbits(n as u32, c_max);

    HealthReport { rct_pass, apt_pass, min_entropy_mbits, samples: n as u32 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log2_of_powers_of_two() {
        // log2(1)=0, log2(2)=1000, log2(4)=2000, log2(256)=8000 mbits.
        assert_eq!(log2_q32_mbits(1 << 32), 0);
        assert_eq!(log2_q32_mbits(2 << 32), 1000);
        assert_eq!(log2_q32_mbits(4 << 32), 2000);
        assert_eq!(log2_q32_mbits(256 << 32), 8000);
    }

    #[test]
    fn log2_of_three_is_about_1_585() {
        // log2(3) ≈ 1.58496 → 1585 mbits (±1 from truncation).
        let m = log2_q32_mbits(3 << 32);
        assert!((1584..=1586).contains(&m), "log2(3) ≈ 1585, got {m}");
    }

    #[test]
    fn isqrt_matches_floor_sqrt() {
        assert_eq!(isqrt_u128(0), 0);
        assert_eq!(isqrt_u128(1), 1);
        assert_eq!(isqrt_u128(15), 3);
        assert_eq!(isqrt_u128(16), 4);
        assert_eq!(isqrt_u128(1_000_000), 1000);
    }

    #[test]
    fn uniform_bytes_estimate_near_eight_bits() {
        // 0..=255 repeated: every value equally likely → near 8 bits.
        let samples: alloc::vec::Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        let r = assess(&samples);
        assert!(r.rct_pass && r.apt_pass);
        // c_max = 16, n = 4096 → p̂ = 1/256, the upper bound pulls it
        // down a little, so expect ~6.5–7.5 bits.
        assert!(
            (6000..=7800).contains(&r.min_entropy_mbits),
            "uniform → ~7 bits, got {} mbits",
            r.min_entropy_mbits,
        );
    }

    #[test]
    fn stuck_source_fails_rct_and_zero_entropy() {
        let samples = [7u8; 64];
        let r = assess(&samples);
        assert!(!r.rct_pass, "a constant source must fail the RCT");
        assert_eq!(r.min_entropy_mbits, 0, "a single value has zero min-entropy");
    }

    #[test]
    fn biased_source_has_low_entropy_estimate() {
        // 90 % zeros, 10 % spread — heavy bias → well under 1 bit.
        let mut samples = alloc::vec::Vec::new();
        for i in 0..1000 {
            samples.push(if i % 10 == 0 { (i % 256) as u8 } else { 0 });
        }
        let r = assess(&samples);
        // p̂ ≈ 0.9 → −log2(0.9) ≈ 0.152 bits.
        assert!(
            r.min_entropy_mbits < 400,
            "90%-biased source ≈ 0.15 bits, got {} mbits",
            r.min_entropy_mbits,
        );
    }

    #[test]
    fn apt_trips_on_a_window_dominated_by_one_value() {
        // A full window where one value takes > 1/4 → APT fails.
        let mut samples = alloc::vec![0u8; APT_WINDOW];
        for (i, s) in samples.iter_mut().enumerate() {
            // Half the window is the value 5, the rest spread.
            *s = if i < APT_WINDOW / 2 { 5 } else { (i % 256) as u8 };
        }
        let r = assess(&samples);
        assert!(!r.apt_pass, "a window 50% one value must fail the APT");
    }

    #[test]
    fn short_batch_does_not_false_fail_apt() {
        // Fewer than APT_WINDOW symbols: the partial window is skipped,
        // so a small all-distinct batch passes.
        let samples: alloc::vec::Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();
        let r = assess(&samples);
        assert!(r.apt_pass, "a sub-window batch must not false-fail the APT");
    }
}
