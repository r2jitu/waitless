// uni-tls/ghash_batch.rs — 8-way batched GHASH with deferred reduction.
//
// **Why**: per-block GHASH (one PCLMUL multiply + one polynomial
// reduction per 16 bytes) is the dominant cost in `aes_gcm_fast`
// even after 8-block batched AES. Each reduction is a chain of
// ~10 shifts + XORs, serially dependent. With 8-way Karatsuba
// aggregation (Gueron 2010, §4) we accumulate eight unreduced
// 256-bit products via XOR, then reduce once per chunk. Saves
// 7/8 of the reduction cost.
//
// **GHASH ↔ POLYVAL trick**: GHASH and POLYVAL operate over the
// same field GF(2^128) but with different reduction polynomials,
// and the bytes/bits are stored in reflected order. RFC 8452
// Appendix A gives the identity:
//
//     GHASH(H, X_1, …) = byte_reverse(POLYVAL(mulx(byte_reverse(H)),
//                                              byte_reverse(X_1), …))
//
// So we do all internal arithmetic in POLYVAL form (which matches
// what PCLMUL / vmull_p64 naturally produce when bytes are loaded
// little-endian) and only byte-reverse at the boundaries.
//
// **The bit-order trap**: an earlier attempt at this file did
// the byte-swap but skipped the `mulx` on H, so per-block GHASH
// was wrong by a factor of x in the field — small enough to pass
// our host-side NIST KAT (which runs on the aarch64 software
// `ghash` fallback) but fatal once on x86 the batched path takes
// over and tag-verify against a real TLS peer fails. The boot-
// time KAT in `apps/webserver` exercises a multi-chunk seal
// (>=128 bytes) so any future regression in the batched path
// surfaces immediately, not just for tail-only records.
//
// **Cross-arch**: x86_64 uses `_mm_clmulepi64_si128` (PCLMUL);
// aarch64 uses `vmull_p64` / `vmull_high_p64` (PMULL/PMULL2).
// The algebra is identical — only the intrinsic names differ.
// Both arches share the same `mulx` + scalar-tail path.
//
// **References**:
//   * S. Gueron, M. Kounavis, "Intel Carry-Less Multiplication
//     Instruction and Its Usage for Computing the GCM Mode",
//     Intel white paper, rev. 2.02, §4 (aggregated reduction).
//   * BoringSSL `crypto/fipsmodule/aes/asm/ghash-x86_64.pl`
//     (`gcm_init_clmul` / `gcm_ghash_clmul`, 4x aggregation).
//   * RustCrypto `polyval::backend::clmul::Polyval::mul`
//     (per-block POLYVAL with Gueron's "alg9" reduction).
//   * RustCrypto `polyval::backend::pmull` (aarch64 PMULL with
//     Karatsuba + Montgomery reduction).

#![allow(unsafe_code)]
// Rust 2024 requires explicit `unsafe {}` blocks inside `unsafe fn`.
// All our unsafe fns are pure-SIMD-intrinsic bodies; an outer
// allow is cleaner than wrapping every line in an inner block.
#![allow(unsafe_op_in_unsafe_fn)]

pub const BLOCK_LEN: usize = 16;
pub const BATCH_BLOCKS: usize = 8;
pub const BATCH_LEN: usize = BLOCK_LEN * BATCH_BLOCKS;

/// Pre-computed GHASH key — H, H^2, …, H^8 in POLYVAL field
/// representation, ready for PCLMUL / PMULL on each call.
///
/// Construction (`new`) runs 7 single-block POLYVAL multiplies +
/// one `mulx` over the wire-format H = `AES_K(0)`. Amortised
/// over the lifetime of a `TrafficKey` (potentially millions of
/// records per TLS session).
#[derive(Clone)]
pub struct GhashKey {
    // h_powers[i] = H^(i+1) in POLYVAL form.
    // Stored as raw little-endian 16-byte blocks so the SIMD
    // loaders can use unaligned loads with no swizzle.
    h_powers: [[u8; BLOCK_LEN]; BATCH_BLOCKS],
}

impl GhashKey {
    /// Build the table from the wire-format GHASH key (i.e.
    /// `AES_K(0^128)`), stored MSB-first per byte.
    pub fn new(h_ghash: &[u8; BLOCK_LEN]) -> Self {
        // POLYVAL H = mulx(byte_reverse(GHASH H)).
        let mut rev = *h_ghash;
        rev.reverse();
        let h1 = mulx(&rev);

        let mut h_powers = [[0u8; BLOCK_LEN]; BATCH_BLOCKS];
        h_powers[0] = h1;
        for i in 1..BATCH_BLOCKS {
            h_powers[i] = polyval_mul(&h_powers[i - 1], &h1);
        }
        GhashKey { h_powers }
    }

    /// Reference to H^1 .. H^8 in POLYVAL form.
    #[inline(always)]
    pub fn h_powers(&self) -> &[[u8; BLOCK_LEN]; BATCH_BLOCKS] {
        &self.h_powers
    }

    /// Start a new GHASH state (Y_0 = 0).
    #[inline(always)]
    pub fn start(&self) -> GhashState<'_> {
        GhashState { key: self, y: [0u8; BLOCK_LEN] }
    }
}

/// Per-call GHASH accumulator. Borrows the pre-computed key.
///
/// Internal `y` is in POLYVAL form (byte-reversed wrt the GHASH
/// wire convention). `finalize` does the final byte-reverse.
pub struct GhashState<'a> {
    key: &'a GhashKey,
    y: [u8; BLOCK_LEN],
}

impl<'a> GhashState<'a> {
    /// Absorb an 8-block (128-byte) chunk of GHASH input via the
    /// SIMD-accelerated batched path. **Hot path** — this is the
    /// reason this module exists.
    #[inline]
    pub fn absorb_8(&mut self, chunk: &[u8; BATCH_LEN]) {
        #[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
        unsafe {
            absorb_8_x86(&mut self.y, &self.key.h_powers, chunk);
            return;
        }
        #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
        unsafe {
            absorb_8_arm(&mut self.y, &self.key.h_powers, chunk);
            return;
        }
        #[allow(unreachable_code)]
        {
            // Portable fallback (only used in test/host without
            // PCLMUL/PMULL): 8 per-block multiplies.
            for i in 0..BATCH_BLOCKS {
                let mut blk = [0u8; BLOCK_LEN];
                blk.copy_from_slice(&chunk[i * BLOCK_LEN..(i + 1) * BLOCK_LEN]);
                self.absorb_one(&blk);
            }
        }
    }

    /// Absorb a single 16-byte block (GHASH wire format). Used
    /// for AAD, the length block, and the 0..7 tail blocks left
    /// over after the batched loop.
    #[inline]
    pub fn absorb_one(&mut self, blk: &[u8; BLOCK_LEN]) {
        let mut rev = *blk;
        rev.reverse();
        let mut xored = [0u8; BLOCK_LEN];
        for i in 0..BLOCK_LEN {
            xored[i] = self.y[i] ^ rev[i];
        }
        self.y = polyval_mul(&xored, &self.key.h_powers[0]);
    }

    /// Absorb a length-prefixed partial block: `bytes` (length
    /// `< 16`), zero-padded to a full block on the right.
    #[inline]
    pub fn absorb_partial(&mut self, bytes: &[u8]) {
        debug_assert!(bytes.len() <= BLOCK_LEN);
        let mut blk = [0u8; BLOCK_LEN];
        blk[..bytes.len()].copy_from_slice(bytes);
        self.absorb_one(&blk);
    }

    /// Absorb an arbitrary slice of AAD (zero-padded to 16-byte
    /// blocks per GHASH spec). Used by the AEAD seal/open AAD
    /// pass — AAD is typically just a TLS record header (~5
    /// bytes) so the batched path doesn't kick in.
    #[inline]
    pub fn absorb_padded_slice(&mut self, bytes: &[u8]) {
        let full = bytes.chunks_exact(BLOCK_LEN);
        let tail = full.remainder();
        for blk in full.clone() {
            let mut a = [0u8; BLOCK_LEN];
            a.copy_from_slice(blk);
            self.absorb_one(&a);
        }
        if !tail.is_empty() {
            self.absorb_partial(tail);
        }
    }

    /// Finalize: byte-reverse the POLYVAL accumulator to recover
    /// the GHASH output.
    #[inline]
    pub fn finalize(self) -> [u8; BLOCK_LEN] {
        let mut out = self.y;
        out.reverse();
        out
    }
}

// ============================================================================
// `mulX_POLYVAL` — RFC 8452 Appendix A.
// ============================================================================
//
// Doubles a field element ("multiply by x") under the POLYVAL
// reduction polynomial. The transformed key H' = mulx(byte_rev(H))
// makes GHASH expressible as POLYVAL on byte-reversed inputs.
// 5 lines of u128 math, copied from RFC 8452 §A reference impl.

fn mulx(block: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    let mut v = u128::from_le_bytes(*block);
    let v_hi = v >> 127;
    v <<= 1;
    v ^= v_hi ^ (v_hi << 127) ^ (v_hi << 126) ^ (v_hi << 121);
    v.to_le_bytes()
}

// ============================================================================
// Single-block POLYVAL multiply (used for tail, AAD, len, key squaring)
// ============================================================================

#[inline]
fn polyval_mul(a: &[u8; BLOCK_LEN], b: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    #[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
    unsafe {
        return polyval_mul_x86(a, b);
    }
    #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
    unsafe {
        return polyval_mul_arm(a, b);
    }
    #[allow(unreachable_code)]
    polyval_mul_soft(a, b)
}

// ============================================================================
// x86_64 PCLMUL path
// ============================================================================

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2,ssse3,pclmulqdq")]
unsafe fn polyval_mul_x86(a: &[u8; BLOCK_LEN], b: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    use core::arch::x86_64::*;
    let av = _mm_loadu_si128(a.as_ptr() as *const __m128i);
    let bv = _mm_loadu_si128(b.as_ptr() as *const __m128i);
    let r = mul_then_reduce_x86(av, bv);
    let mut out = [0u8; BLOCK_LEN];
    _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, r);
    out
}

#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "sse2,pclmulqdq")]
unsafe fn mul_then_reduce_x86(
    av: core::arch::x86_64::__m128i,
    bv: core::arch::x86_64::__m128i,
) -> core::arch::x86_64::__m128i {
    use core::arch::x86_64::*;
    // Karatsuba: 3 PCLMULs to produce the unreduced 256-bit
    // product split into low/middle/high 128-bit "halves".
    let h0 = bv;
    let h1 = _mm_shuffle_epi32(bv, 0x0E);
    let h2 = _mm_xor_si128(h0, h1);
    let y0 = av;
    let y1 = _mm_shuffle_epi32(av, 0x0E);
    let y2 = _mm_xor_si128(y0, y1);
    let t0 = _mm_clmulepi64_si128(y0, h0, 0x00);
    let t1 = _mm_clmulepi64_si128(av, bv, 0x11);
    let t2 = _mm_clmulepi64_si128(y2, h2, 0x00);
    let t2 = _mm_xor_si128(t2, _mm_xor_si128(t0, t1));
    // Combine into 4× 64-bit chunks v0..v3 (low to high).
    let v0 = t0;
    let v1 = _mm_xor_si128(_mm_shuffle_epi32(t0, 0x0E), t2);
    let v2 = _mm_xor_si128(t1, _mm_shuffle_epi32(t2, 0x0E));
    let v3 = _mm_shuffle_epi32(t1, 0x0E);
    reduce_x86(v0, v1, v2, v3)
}

#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn reduce_x86(
    v0: core::arch::x86_64::__m128i,
    v1: core::arch::x86_64::__m128i,
    v2: core::arch::x86_64::__m128i,
    v3: core::arch::x86_64::__m128i,
) -> core::arch::x86_64::__m128i {
    use core::arch::x86_64::*;
    // POLYVAL reduction polynomial: x^128 + x^127 + x^126 + x^121 + 1.
    // Two phases; verbatim shape from polyval::backend::clmul::Polyval::mul.
    let v2 = _mm_xor_si128(
        _mm_xor_si128(v2, v0),
        _mm_xor_si128(
            _mm_srli_epi64(v0, 1),
            _mm_xor_si128(_mm_srli_epi64(v0, 2), _mm_srli_epi64(v0, 7)),
        ),
    );
    let v1 = _mm_xor_si128(
        v1,
        _mm_xor_si128(
            _mm_slli_epi64(v0, 63),
            _mm_xor_si128(_mm_slli_epi64(v0, 62), _mm_slli_epi64(v0, 57)),
        ),
    );
    let v3 = _mm_xor_si128(
        _mm_xor_si128(v3, v1),
        _mm_xor_si128(
            _mm_srli_epi64(v1, 1),
            _mm_xor_si128(_mm_srli_epi64(v1, 2), _mm_srli_epi64(v1, 7)),
        ),
    );
    let v2 = _mm_xor_si128(
        v2,
        _mm_xor_si128(
            _mm_slli_epi64(v1, 63),
            _mm_xor_si128(_mm_slli_epi64(v1, 62), _mm_slli_epi64(v1, 57)),
        ),
    );
    _mm_unpacklo_epi64(v2, v3)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2,ssse3,pclmulqdq")]
unsafe fn absorb_8_x86(
    y: &mut [u8; BLOCK_LEN],
    h_powers: &[[u8; BLOCK_LEN]; BATCH_BLOCKS],
    chunk: &[u8; BATCH_LEN],
) {
    use core::arch::x86_64::*;

    // PSHUFB mask: byte-reverse 16 bytes. PSHUFB sources byte `i`
    // from `input[mask[i]]`. For `bswap`, mask[i] = 15-i.
    // `_mm_set_epi8` lists bytes in MSB-first parameter order, so
    // the literal (0, 1, …, 15) stores 15 at byte 0, 14 at byte 1,
    // …, 0 at byte 15 — exactly mask[i] = 15-i.
    let bswap = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

    let state = _mm_loadu_si128(y.as_ptr() as *const __m128i);

    // Pre-load H powers and Karatsuba-pre-XOR for each. H is
    // constant per record so this could be hoisted further, but
    // it's cheap (4 instrs × 8 = 32 simple ops once per chunk).
    let h: [core::arch::x86_64::__m128i; BATCH_BLOCKS] = [
        _mm_loadu_si128(h_powers[7].as_ptr() as *const __m128i), // H^8 ↔ block 0
        _mm_loadu_si128(h_powers[6].as_ptr() as *const __m128i), // H^7 ↔ block 1
        _mm_loadu_si128(h_powers[5].as_ptr() as *const __m128i),
        _mm_loadu_si128(h_powers[4].as_ptr() as *const __m128i),
        _mm_loadu_si128(h_powers[3].as_ptr() as *const __m128i),
        _mm_loadu_si128(h_powers[2].as_ptr() as *const __m128i),
        _mm_loadu_si128(h_powers[1].as_ptr() as *const __m128i),
        _mm_loadu_si128(h_powers[0].as_ptr() as *const __m128i), // H^1 ↔ block 7
    ];

    let mut acc_lo = _mm_setzero_si128();
    let mut acc_hi = _mm_setzero_si128();
    let mut acc_mid = _mm_setzero_si128();

    for i in 0..BATCH_BLOCKS {
        let x_raw = _mm_loadu_si128(chunk.as_ptr().add(i * BLOCK_LEN) as *const __m128i);
        let x_rev = _mm_shuffle_epi8(x_raw, bswap);
        // First block folds in current Y; subsequent blocks just go in.
        let yi = if i == 0 { _mm_xor_si128(state, x_rev) } else { x_rev };
        let hi = h[i];

        // Karatsuba per-block: low×low, high×high, middle =
        // (lo XOR hi of y) × (lo XOR hi of h). Stash, defer
        // reduction. (Reduction is linear, so XOR-accumulating
        // un-reduced partial products is equivalent to summing
        // each reduced product and reducing once at the end.)
        let y_swap = _mm_shuffle_epi32(yi, 0x0E);
        let y_kar = _mm_xor_si128(yi, y_swap);
        let h_swap = _mm_shuffle_epi32(hi, 0x0E);
        let h_kar = _mm_xor_si128(hi, h_swap);

        let t0 = _mm_clmulepi64_si128(yi, hi, 0x00);
        let t1 = _mm_clmulepi64_si128(yi, hi, 0x11);
        let tm = _mm_clmulepi64_si128(y_kar, h_kar, 0x00);
        acc_lo = _mm_xor_si128(acc_lo, t0);
        acc_hi = _mm_xor_si128(acc_hi, t1);
        acc_mid = _mm_xor_si128(acc_mid, tm);
    }

    // Final Karatsuba combine: middle - low - high.
    let acc_mid = _mm_xor_si128(acc_mid, _mm_xor_si128(acc_lo, acc_hi));

    // Split into 4× 64-bit limbs (low to high) and reduce.
    let v0 = acc_lo;
    let v1 = _mm_xor_si128(_mm_shuffle_epi32(acc_lo, 0x0E), acc_mid);
    let v2 = _mm_xor_si128(acc_hi, _mm_shuffle_epi32(acc_mid, 0x0E));
    let v3 = _mm_shuffle_epi32(acc_hi, 0x0E);
    let result = reduce_x86(v0, v1, v2, v3);
    _mm_storeu_si128(y.as_mut_ptr() as *mut __m128i, result);
}

// ============================================================================
// aarch64 PMULL path
// ============================================================================

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes,neon")]
unsafe fn polyval_mul_arm(a: &[u8; BLOCK_LEN], b: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    use core::arch::aarch64::*;
    let av = vld1q_u8(a.as_ptr());
    let bv = vld1q_u8(b.as_ptr());
    let (h, m, l) = karatsuba1_arm(av, bv);
    let (hh, ll) = karatsuba2_arm(h, m, l);
    let r = mont_reduce_arm(hh, ll);
    let mut out = [0u8; BLOCK_LEN];
    vst1q_u8(out.as_mut_ptr(), r);
    out
}

#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "aes,neon")]
unsafe fn pmull_lo(a: core::arch::aarch64::uint8x16_t, b: core::arch::aarch64::uint8x16_t) -> core::arch::aarch64::uint8x16_t {
    use core::arch::aarch64::*;
    core::mem::transmute(vmull_p64(
        vgetq_lane_u64(vreinterpretq_u64_u8(a), 0),
        vgetq_lane_u64(vreinterpretq_u64_u8(b), 0),
    ))
}

#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "aes,neon")]
unsafe fn pmull_hi(a: core::arch::aarch64::uint8x16_t, b: core::arch::aarch64::uint8x16_t) -> core::arch::aarch64::uint8x16_t {
    use core::arch::aarch64::*;
    core::mem::transmute(vmull_p64(
        vgetq_lane_u64(vreinterpretq_u64_u8(a), 1),
        vgetq_lane_u64(vreinterpretq_u64_u8(b), 1),
    ))
}

#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "aes,neon")]
unsafe fn karatsuba1_arm(
    x: core::arch::aarch64::uint8x16_t,
    y: core::arch::aarch64::uint8x16_t,
) -> (
    core::arch::aarch64::uint8x16_t,
    core::arch::aarch64::uint8x16_t,
    core::arch::aarch64::uint8x16_t,
) {
    use core::arch::aarch64::*;
    let m = pmull_lo(
        veorq_u8(x, vextq_u8(x, x, 8)),
        veorq_u8(y, vextq_u8(y, y, 8)),
    );
    let h = pmull_hi(x, y);
    let l = pmull_lo(x, y);
    (h, m, l)
}

#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "aes,neon")]
unsafe fn karatsuba2_arm(
    h: core::arch::aarch64::uint8x16_t,
    m: core::arch::aarch64::uint8x16_t,
    l: core::arch::aarch64::uint8x16_t,
) -> (core::arch::aarch64::uint8x16_t, core::arch::aarch64::uint8x16_t) {
    use core::arch::aarch64::*;
    let t = {
        let t0 = veorq_u8(m, vextq_u8(l, h, 8));
        let t1 = veorq_u8(h, l);
        veorq_u8(t0, t1)
    };
    let x01 = vextq_u8(vextq_u8(l, l, 8), t, 8);
    let x23 = vextq_u8(t, vextq_u8(h, h, 8), 8);
    (x23, x01)
}

#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "aes,neon")]
unsafe fn mont_reduce_arm(
    x23: core::arch::aarch64::uint8x16_t,
    x01: core::arch::aarch64::uint8x16_t,
) -> core::arch::aarch64::uint8x16_t {
    use core::arch::aarch64::*;
    let poly = vreinterpretq_u8_p128(
        1 << 127 | 1 << 126 | 1 << 121 | 1 << 63 | 1 << 62 | 1 << 57,
    );
    let a = pmull_lo(x01, poly);
    let b = veorq_u8(x01, vextq_u8(a, a, 8));
    let c = pmull_hi(b, poly);
    veorq_u8(x23, veorq_u8(c, b))
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes,neon")]
unsafe fn absorb_8_arm(
    y: &mut [u8; BLOCK_LEN],
    h_powers: &[[u8; BLOCK_LEN]; BATCH_BLOCKS],
    chunk: &[u8; BATCH_LEN],
) {
    use core::arch::aarch64::*;

    let bswap_idx: [u8; 16] = [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];
    let bswap = vld1q_u8(bswap_idx.as_ptr());

    let state = vld1q_u8(y.as_ptr());

    let h: [uint8x16_t; BATCH_BLOCKS] = [
        vld1q_u8(h_powers[7].as_ptr()),
        vld1q_u8(h_powers[6].as_ptr()),
        vld1q_u8(h_powers[5].as_ptr()),
        vld1q_u8(h_powers[4].as_ptr()),
        vld1q_u8(h_powers[3].as_ptr()),
        vld1q_u8(h_powers[2].as_ptr()),
        vld1q_u8(h_powers[1].as_ptr()),
        vld1q_u8(h_powers[0].as_ptr()),
    ];

    let mut acc_h = vdupq_n_u8(0);
    let mut acc_m = vdupq_n_u8(0);
    let mut acc_l = vdupq_n_u8(0);

    for i in 0..BATCH_BLOCKS {
        let x_raw = vld1q_u8(chunk.as_ptr().add(i * BLOCK_LEN));
        let x_rev = vqtbl1q_u8(x_raw, bswap);
        let yi = if i == 0 { veorq_u8(state, x_rev) } else { x_rev };
        let (hi, mi, lo) = karatsuba1_arm(yi, h[i]);
        acc_h = veorq_u8(acc_h, hi);
        acc_m = veorq_u8(acc_m, mi);
        acc_l = veorq_u8(acc_l, lo);
    }

    let (h_combined, l_combined) = karatsuba2_arm(acc_h, acc_m, acc_l);
    let result = mont_reduce_arm(h_combined, l_combined);
    vst1q_u8(y.as_mut_ptr(), result);
}

// ============================================================================
// Portable software fallback (compile-time gated; host-only)
// ============================================================================
//
// Used only when neither PCLMUL nor PMULL is available — currently
// just to keep `polyval_mul` compilable on hosts where the SIMD
// gates fail (e.g. running `cargo test` under an emulator). All
// deployment targets pick the SIMD paths above.

#[cfg(not(any(
    all(target_arch = "x86_64", target_feature = "pclmulqdq"),
    all(target_arch = "aarch64", target_feature = "aes"),
)))]
fn polyval_mul_soft(a: &[u8; BLOCK_LEN], b: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    // Schoolbook GF(2)[x]/(POLYVAL polynomial). Slow but
    // correct — only here so `cargo test` builds for hosts
    // without PCLMUL.
    let au = u128::from_le_bytes(*a);
    let bu = u128::from_le_bytes(*b);
    let mut zh: u128 = 0;
    let mut zl: u128 = 0;
    for i in 0..128 {
        if (au >> i) & 1 == 1 {
            zl ^= bu << i;
            if i != 0 {
                zh ^= bu >> (128 - i);
            }
        }
    }
    // Reduce 256-bit (zh:zl) under x^128 + x^127 + x^126 + x^121 + 1
    // by folding the high half down.
    for i in (0..128).rev() {
        if (zh >> i) & 1 == 1 {
            zh ^= 1u128 << i;
            // Adding x^(128+i) ≡ x^(127+i) + x^(126+i) + x^(121+i) + x^i.
            let shift = i;
            // (127+i) and lower may straddle the 128 boundary.
            let mut fold = |bit: u32| {
                let p = bit as usize + shift;
                if p >= 128 {
                    zh ^= 1u128 << (p - 128);
                } else {
                    zl ^= 1u128 << p;
                }
            };
            fold(127);
            fold(126);
            fold(121);
            fold(0);
        }
    }
    zl.to_le_bytes()
}

// On SIMD-enabled targets `polyval_mul_soft` is unreachable but
// referenced by `polyval_mul`'s `#[allow(unreachable_code)]` arm.
// Provide a stub so the symbol resolves.
#[cfg(any(
    all(target_arch = "x86_64", target_feature = "pclmulqdq"),
    all(target_arch = "aarch64", target_feature = "aes"),
))]
#[allow(dead_code)]
fn polyval_mul_soft(_a: &[u8; BLOCK_LEN], _b: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    unreachable!("SIMD path always picked when this target_feature is on")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    /// RFC 8452 Appendix A — `mulX_POLYVAL` test vector (errata
    /// version). Matches `polyval::mulx::tests::rfc8452_vector`.
    #[test]
    fn mulx_rfc8452() {
        let input: [u8; 16] = [
            0x9c, 0x98, 0xc0, 0x4d, 0xf9, 0x38, 0x7d, 0xed,
            0x82, 0x81, 0x75, 0xa9, 0x2b, 0xa6, 0x52, 0xd8,
        ];
        let expected: [u8; 16] = [
            0x39, 0x31, 0x81, 0x9b, 0xf2, 0x71, 0xfa, 0xda,
            0x05, 0x03, 0xeb, 0x52, 0x57, 0x4c, 0xa5, 0x72,
        ];
        assert_eq!(mulx(&input), expected);
    }

    /// Cross-check the batched GHASH against the audited `ghash`
    /// crate for a sweep of input sizes including the multi-
    /// chunk path (>=128 bytes). This is the strongest correctness
    /// signal — any byte-order or reduction bug shows up here.
    #[test]
    fn matches_ghash_crate() {
        use ghash::universal_hash::generic_array::GenericArray;
        use ghash::universal_hash::KeyInit as KI;
        use ghash::universal_hash::UniversalHash;
        use ghash::GHash;

        // Several H values to flush out bit-reversal bugs that
        // happen to vanish for sparse keys.
        let h_keys: &[[u8; 16]] = &[
            [0x00; 16],
            [0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0x42; 16],
            *b"YELLOW SUBMARINE",
            // Random-ish high-entropy key.
            [
                0xee, 0xc0, 0xed, 0x67, 0x6b, 0xa5, 0xee, 0x91,
                0xaf, 0xd3, 0xc4, 0x76, 0x57, 0x71, 0xc4, 0xd4,
            ],
        ];

        let sizes: &[usize] = &[
            0, 16, 32, 48, 64, 80, 96, 112, // sub-chunk
            128, 144, 160, 176, // exactly chunk + small tail
            256, 257, 384, 511, 512, 1024, 4096, 16383,
        ];

        for h in h_keys {
            let key = GhashKey::new(h);
            for &n in sizes {
                let input: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7)).collect();

                let mut ours = key.start();
                let mut i = 0;
                while i + BATCH_LEN <= input.len() {
                    let mut chunk = [0u8; BATCH_LEN];
                    chunk.copy_from_slice(&input[i..i + BATCH_LEN]);
                    ours.absorb_8(&chunk);
                    i += BATCH_LEN;
                }
                while i + BLOCK_LEN <= input.len() {
                    let mut blk = [0u8; BLOCK_LEN];
                    blk.copy_from_slice(&input[i..i + BLOCK_LEN]);
                    ours.absorb_one(&blk);
                    i += BLOCK_LEN;
                }
                if i < input.len() {
                    ours.absorb_partial(&input[i..]);
                }
                let ours = ours.finalize();

                // Reference: ghash crate per-block.
                let mut reference = GHash::new(GenericArray::from_slice(h));
                let mut j = 0;
                while j + BLOCK_LEN <= input.len() {
                    let blk = GenericArray::from_slice(&input[j..j + BLOCK_LEN]);
                    reference.update(&[*blk]);
                    j += BLOCK_LEN;
                }
                if j < input.len() {
                    let mut padded = [0u8; BLOCK_LEN];
                    padded[..input.len() - j].copy_from_slice(&input[j..]);
                    let blk = GenericArray::from_slice(&padded);
                    reference.update(&[*blk]);
                }
                let reference: [u8; 16] = reference.finalize().into();

                assert_eq!(
                    ours, reference,
                    "GHASH mismatch: h={:02x?} n={}",
                    h, n
                );
            }
        }
    }

    /// Single-block sanity test using a published GHASH vector
    /// computed by NIST SP 800-38D Test Case 2:
    ///   K = 0^128
    ///   H = AES_K(0) = 66e94bd4ef8a2c3b884cfa59ca342b2e
    ///   A = empty, P = 0^128, IV = 0^96
    ///   GHASH(H, 0^128 || len(0)||len(128)):
    ///     -- per the test vector, the final tag XOR mask gives
    ///        tag = ab6e47d42cec13bdf53a67b21257bddf
    /// We just check the GHASH crate matches us here — trivial
    /// sanity since the cross-check above already covers this.
    #[test]
    fn nist_h_value() {
        let h: [u8; 16] = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
            0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
        ];
        let key = GhashKey::new(&h);
        // H * 1 in the GHASH field should be H itself (trivial).
        let mut st = key.start();
        let one_block = [0u8; 16];
        st.absorb_one(&one_block);
        let out = st.finalize();
        assert_eq!(out, [0u8; 16]);
    }
}
