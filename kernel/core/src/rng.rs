// kernel_core/rng.rs — host-buildable RNG link seam.
//
// `fill_bytes` is the entropy entry point for the host-buildable
// crates that sit below `//uni` and so cannot reach the `uni::rng`
// seam — chiefly `net_tcp`, which draws its TCP initial sequence
// number here.
//
// It mirrors the `cpu_id` link seam:
//
//   * `target_os = "none"` → resolves, via the `extern "Rust"`
//     symbol `__uni_kernel_rng_fill`, to `//kernel`'s real generator
//     (jitter entropy + RDRAND seed, expanded through a SHA-256 hash
//     chain). `kernel_core` is the lower crate and cannot call up
//     into `//kernel`, so it declares the symbol and `//kernel`
//     defines it.
//
//   * host build → a deterministic SplitMix64 stream. RNG-dependent
//     unit tests (a `tcp_receive` conformance harness asserting on
//     the server's ISN) want a reproducible sequence, not real
//     entropy — this is the deliberate difference from `uni::rng`,
//     whose host branch calls `getentropy(2)`.

/// Fill `dest` with random bytes.
///
/// See the module comment for the per-target backend. The compile-
/// time `cfg` (not a function pointer) keeps the bare-metal path a
/// single direct call into the seam symbol.
#[cfg(target_os = "none")]
pub fn fill_bytes(dest: &mut [u8]) {
    unsafe extern "Rust" {
        fn __uni_kernel_rng_fill(dest: &mut [u8]);
    }
    // SAFETY: `//kernel` defines this `#[no_mangle]` symbol, and
    // every `os:none` binary that links `kernel_core` also links
    // `//kernel` (it is the foundational crate).
    unsafe { __uni_kernel_rng_fill(dest) }
}

/// Host build: a deterministic SplitMix64 stream — reproducible
/// across runs so RNG-dependent unit tests are stable.
#[cfg(not(target_os = "none"))]
pub fn fill_bytes(dest: &mut [u8]) {
    use core::sync::atomic::{AtomicU64, Ordering};

    // Process-global stream state. Advances per 8-byte block, so
    // successive calls (and successive blocks within a call) never
    // repeat. Seeded with a fixed constant — determinism is the point.
    static STATE: AtomicU64 = AtomicU64::new(0x0123_4567_89ab_cdef);

    const GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;
    for block in dest.chunks_mut(8) {
        let mut z = STATE
            .fetch_add(GAMMA, Ordering::Relaxed)
            .wrapping_add(GAMMA);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        let bytes = z.to_le_bytes();
        block.copy_from_slice(&bytes[..block.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_lengths_that_are_not_a_multiple_of_eight() {
        // The `chunks_mut(8)` tail block must `copy_from_slice` a
        // matching-length prefix — a mismatch would panic here.
        let mut buf = [0u8; 31];
        for len in [0usize, 1, 7, 8, 9, 17, 31] {
            fill_bytes(&mut buf[..len]);
        }
    }

    #[test]
    fn produces_nonzero_output() {
        let mut buf = [0u8; 32];
        fill_bytes(&mut buf);
        assert!(buf.iter().any(|&b| b != 0), "fill left an all-zero buffer");
    }

    #[test]
    fn successive_calls_advance_the_stream() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_bytes(&mut a);
        fill_bytes(&mut b);
        assert_ne!(a, b, "the deterministic stream must advance between calls");
    }
}
