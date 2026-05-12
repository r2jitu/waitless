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
// **Cross-arch**: x86_64 uses `_mm_clmulepi64_si128` (PCLMUL);
// aarch64 uses `vmull_p64` / `vmull_high_p64` (PMULL/PMULL2).
// The algebra is identical — only the intrinsic names differ.
// Both arches share the same `mulx` + scalar-tail path.
//
// **Module layout**: the arch-specific PCLMUL / PMULL math lives
// behind `xmm` (x86) / `neon` (aarch64) submodules that expose
// `Acc` accumulators + `karatsuba_accumulate` + `finalize_chunk`
// primitives. `absorb_8` (this file's public batched API) is one
// caller; `aes_gcm_fast::stitched_chunk_*` is the other (which
// keeps ciphertext in __m128i / uint8x16_t registers across the
// AES-CTR XOR and the GHASH absorb instead of round-tripping
// through the buffer).
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
#[derive(Clone)]
pub struct GhashKey {
    h_powers: [[u8; BLOCK_LEN]; BATCH_BLOCKS],
}

impl GhashKey {
    /// Build the table from the wire-format GHASH key (i.e.
    /// `AES_K(0^128)`), stored MSB-first per byte.
    pub fn new(h_ghash: &[u8; BLOCK_LEN]) -> Self {
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

    /// Read-only reference to H^1 .. H^8 in POLYVAL form.
    #[inline]
    pub(crate) fn h_powers(&self) -> &[[u8; BLOCK_LEN]; BATCH_BLOCKS] {
        &self.h_powers
    }

    /// Start a new GHASH state (Y_0 = 0).
    #[inline]
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
    /// SIMD-accelerated batched path. **Hot path** for the open
    /// (decrypt-then-auth) flow; the seal path now uses
    /// `aes_gcm_fast::stitched_chunk_*` which fuses this with the
    /// AES-CTR XOR.
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

    /// (stitched-path helper) View the current POLYVAL-form state
    /// for reading into a register at the start of a stitched
    /// chunk loop.
    #[inline]
    pub(crate) fn polyval_state(&self) -> &[u8; BLOCK_LEN] {
        &self.y
    }

    /// (stitched-path helper) Overwrite the POLYVAL-form state
    /// from a register at the end of a stitched chunk loop.
    #[inline]
    pub(crate) fn set_polyval_state(&mut self, y: [u8; BLOCK_LEN]) {
        self.y = y;
    }

    /// (stitched-path helper) Reach the borrowed key to load
    /// H^1..H^8 into registers.
    #[inline]
    pub(crate) fn key(&self) -> &'a GhashKey {
        self.key
    }
}

// ============================================================================
// `mulX_POLYVAL` — RFC 8452 Appendix A.
// ============================================================================

fn mulx(block: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    let mut v = u128::from_le_bytes(*block);
    let v_hi = v >> 127;
    v <<= 1;
    v ^= v_hi ^ (v_hi << 127) ^ (v_hi << 126) ^ (v_hi << 121);
    v.to_le_bytes()
}

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
// x86_64 PCLMUL primitives — shared by `absorb_8_x86` (this file)
// and `aes_gcm_fast::stitched_chunk_x86` (the stitched seal path).
// ============================================================================

#[cfg(target_arch = "x86_64")]
pub(crate) mod xmm {
    use super::{BATCH_BLOCKS, BLOCK_LEN};
    use core::arch::x86_64::*;

    /// Deferred-reduction Karatsuba accumulator. Holds the three
    /// 128-bit XOR sums of (lo×lo), (hi×hi), and the mid Karatsuba
    /// product across all blocks in the current chunk.
    #[derive(Clone, Copy)]
    pub(crate) struct Acc {
        pub lo: __m128i,
        pub hi: __m128i,
        pub mid: __m128i,
    }

    /// PSHUFB mask that byte-reverses a 16-byte register. PSHUFB
    /// sources byte `i` from `input[mask[i]]`; we want mask[i] =
    /// 15-i. `_mm_set_epi8` takes bytes in MSB-first parameter
    /// order, so the literal `(0,1,…,15)` stores 15 at byte 0,
    /// 14 at byte 1, …, 0 at byte 15.
    #[inline]
    #[target_feature(enable = "sse2")]
    pub(crate) unsafe fn bswap_mask() -> __m128i {
        _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
    }

    /// Load H^1..H^8 in the order block i pairs with H^(8-i).
    #[inline]
    #[target_feature(enable = "sse2")]
    pub(crate) unsafe fn load_h_powers(
        h_powers: &[[u8; BLOCK_LEN]; BATCH_BLOCKS],
    ) -> [__m128i; BATCH_BLOCKS] {
        [
            _mm_loadu_si128(h_powers[7].as_ptr() as *const __m128i),
            _mm_loadu_si128(h_powers[6].as_ptr() as *const __m128i),
            _mm_loadu_si128(h_powers[5].as_ptr() as *const __m128i),
            _mm_loadu_si128(h_powers[4].as_ptr() as *const __m128i),
            _mm_loadu_si128(h_powers[3].as_ptr() as *const __m128i),
            _mm_loadu_si128(h_powers[2].as_ptr() as *const __m128i),
            _mm_loadu_si128(h_powers[1].as_ptr() as *const __m128i),
            _mm_loadu_si128(h_powers[0].as_ptr() as *const __m128i),
        ]
    }

    #[inline]
    #[target_feature(enable = "sse2")]
    pub(crate) unsafe fn acc_zero() -> Acc {
        let z = _mm_setzero_si128();
        Acc { lo: z, hi: z, mid: z }
    }

    /// Karatsuba per-block: 3 PCLMULs producing (lo×lo, hi×hi,
    /// mid). XOR-fold into `acc` — *no reduction yet*. Caller
    /// runs `acc_reduce` once after all 8 blocks are absorbed.
    #[inline]
    #[target_feature(enable = "sse2,pclmulqdq")]
    pub(crate) unsafe fn karatsuba_accumulate(acc: &mut Acc, y: __m128i, h: __m128i) {
        let y_swap = _mm_shuffle_epi32(y, 0x0E);
        let y_kar = _mm_xor_si128(y, y_swap);
        let h_swap = _mm_shuffle_epi32(h, 0x0E);
        let h_kar = _mm_xor_si128(h, h_swap);
        let t0 = _mm_clmulepi64_si128(y, h, 0x00);
        let t1 = _mm_clmulepi64_si128(y, h, 0x11);
        let tm = _mm_clmulepi64_si128(y_kar, h_kar, 0x00);
        acc.lo = _mm_xor_si128(acc.lo, t0);
        acc.hi = _mm_xor_si128(acc.hi, t1);
        acc.mid = _mm_xor_si128(acc.mid, tm);
    }

    /// Karatsuba combine + POLYVAL reduction. Output is the new
    /// POLYVAL-form state (still in xmm register; byte-reverse at
    /// the seal boundary, not here).
    #[inline]
    #[target_feature(enable = "sse2,pclmulqdq")]
    pub(crate) unsafe fn acc_reduce(acc: Acc) -> __m128i {
        // Karatsuba combine: mid ^= lo ^ hi.
        let mid = _mm_xor_si128(acc.mid, _mm_xor_si128(acc.lo, acc.hi));
        // Split into 4× 64-bit limbs (low to high).
        let v0 = acc.lo;
        let v1 = _mm_xor_si128(_mm_shuffle_epi32(acc.lo, 0x0E), mid);
        let v2 = _mm_xor_si128(acc.hi, _mm_shuffle_epi32(mid, 0x0E));
        let v3 = _mm_shuffle_epi32(acc.hi, 0x0E);
        reduce(v0, v1, v2, v3)
    }

    /// POLYVAL reduction polynomial: x^128 + x^127 + x^126 + x^121 + 1.
    /// Two phases; verbatim shape from
    /// `polyval::backend::clmul::Polyval::mul`.
    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn reduce(v0: __m128i, v1: __m128i, v2: __m128i, v3: __m128i) -> __m128i {
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

    /// Single-block POLYVAL mul (key squaring at init, tail/AAD).
    #[inline]
    #[target_feature(enable = "sse2,pclmulqdq")]
    pub(super) unsafe fn polyval_mul_block(
        a: &[u8; BLOCK_LEN],
        b: &[u8; BLOCK_LEN],
    ) -> [u8; BLOCK_LEN] {
        let av = _mm_loadu_si128(a.as_ptr() as *const __m128i);
        let bv = _mm_loadu_si128(b.as_ptr() as *const __m128i);
        let mut acc = acc_zero();
        karatsuba_accumulate(&mut acc, av, bv);
        let r = acc_reduce(acc);
        let mut out = [0u8; BLOCK_LEN];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, r);
        out
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2,pclmulqdq")]
unsafe fn polyval_mul_x86(a: &[u8; BLOCK_LEN], b: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    xmm::polyval_mul_block(a, b)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2,ssse3,pclmulqdq")]
unsafe fn absorb_8_x86(
    y: &mut [u8; BLOCK_LEN],
    h_powers: &[[u8; BLOCK_LEN]; BATCH_BLOCKS],
    chunk: &[u8; BATCH_LEN],
) {
    use core::arch::x86_64::*;
    let bswap = xmm::bswap_mask();
    let state = _mm_loadu_si128(y.as_ptr() as *const __m128i);
    let h = xmm::load_h_powers(h_powers);
    let mut acc = xmm::acc_zero();

    for i in 0..BATCH_BLOCKS {
        let x_raw = _mm_loadu_si128(chunk.as_ptr().add(i * BLOCK_LEN) as *const __m128i);
        let x_rev = _mm_shuffle_epi8(x_raw, bswap);
        let yi = if i == 0 { _mm_xor_si128(state, x_rev) } else { x_rev };
        xmm::karatsuba_accumulate(&mut acc, yi, h[i]);
    }
    let result = xmm::acc_reduce(acc);
    _mm_storeu_si128(y.as_mut_ptr() as *mut __m128i, result);
}

// ============================================================================
// aarch64 PMULL primitives — shared by `absorb_8_arm` (this file)
// and `aes_gcm_fast::stitched_chunk_arm` (the stitched seal path).
// ============================================================================

#[cfg(target_arch = "aarch64")]
pub(crate) mod neon {
    use super::{BATCH_BLOCKS, BLOCK_LEN};
    use core::arch::aarch64::*;

    /// Deferred-reduction Karatsuba accumulator. Holds the three
    /// 128-bit XOR sums of `pmull_hi`, `pmull_lo`, and the mid
    /// Karatsuba product across all blocks in the current chunk.
    #[derive(Clone, Copy)]
    pub(crate) struct Acc {
        pub h: uint8x16_t,
        pub m: uint8x16_t,
        pub l: uint8x16_t,
    }

    /// TBL indices that byte-reverse a 16-byte register.
    #[inline]
    #[target_feature(enable = "neon")]
    pub(crate) unsafe fn bswap_indices() -> uint8x16_t {
        const IDX: [u8; 16] = [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];
        vld1q_u8(IDX.as_ptr())
    }

    #[inline]
    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn load_h_powers(
        h_powers: &[[u8; BLOCK_LEN]; BATCH_BLOCKS],
    ) -> [uint8x16_t; BATCH_BLOCKS] {
        [
            vld1q_u8(h_powers[7].as_ptr()),
            vld1q_u8(h_powers[6].as_ptr()),
            vld1q_u8(h_powers[5].as_ptr()),
            vld1q_u8(h_powers[4].as_ptr()),
            vld1q_u8(h_powers[3].as_ptr()),
            vld1q_u8(h_powers[2].as_ptr()),
            vld1q_u8(h_powers[1].as_ptr()),
            vld1q_u8(h_powers[0].as_ptr()),
        ]
    }

    #[inline]
    #[target_feature(enable = "neon")]
    pub(crate) unsafe fn acc_zero() -> Acc {
        let z = vdupq_n_u8(0);
        Acc { h: z, m: z, l: z }
    }

    #[inline]
    #[target_feature(enable = "aes,neon")]
    unsafe fn pmull_lo(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
        core::mem::transmute(vmull_p64(
            vgetq_lane_u64(vreinterpretq_u64_u8(a), 0),
            vgetq_lane_u64(vreinterpretq_u64_u8(b), 0),
        ))
    }

    #[inline]
    #[target_feature(enable = "aes,neon")]
    unsafe fn pmull_hi(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
        core::mem::transmute(vmull_p64(
            vgetq_lane_u64(vreinterpretq_u64_u8(a), 1),
            vgetq_lane_u64(vreinterpretq_u64_u8(b), 1),
        ))
    }

    /// Karatsuba per-block (3 PMULLs); XOR-fold into `acc` —
    /// *no reduction yet*.
    #[inline]
    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn karatsuba_accumulate(acc: &mut Acc, y: uint8x16_t, h: uint8x16_t) {
        let mid = pmull_lo(
            veorq_u8(y, vextq_u8(y, y, 8)),
            veorq_u8(h, vextq_u8(h, h, 8)),
        );
        let hi = pmull_hi(y, h);
        let lo = pmull_lo(y, h);
        acc.h = veorq_u8(acc.h, hi);
        acc.m = veorq_u8(acc.m, mid);
        acc.l = veorq_u8(acc.l, lo);
    }

    /// Karatsuba combine + Montgomery reduction. Output: new
    /// POLYVAL-form state in a 128-bit register.
    #[inline]
    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn acc_reduce(acc: Acc) -> uint8x16_t {
        let (x23, x01) = karatsuba2(acc.h, acc.m, acc.l);
        mont_reduce(x23, x01)
    }

    /// Karatsuba combine: (h, m, l) → 256-bit product (x23 high,
    /// x01 low). Verbatim shape from
    /// `polyval::backend::pmull::karatsuba2`.
    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn karatsuba2(
        h: uint8x16_t,
        m: uint8x16_t,
        l: uint8x16_t,
    ) -> (uint8x16_t, uint8x16_t) {
        let t = {
            let t0 = veorq_u8(m, vextq_u8(l, h, 8));
            let t1 = veorq_u8(h, l);
            veorq_u8(t0, t1)
        };
        let x01 = vextq_u8(vextq_u8(l, l, 8), t, 8);
        let x23 = vextq_u8(t, vextq_u8(h, h, 8), 8);
        (x23, x01)
    }

    /// POLYVAL Montgomery reduction; verbatim shape from
    /// `polyval::backend::pmull::mont_reduce`.
    #[inline]
    #[target_feature(enable = "aes,neon")]
    unsafe fn mont_reduce(x23: uint8x16_t, x01: uint8x16_t) -> uint8x16_t {
        let poly = vreinterpretq_u8_p128(
            1 << 127 | 1 << 126 | 1 << 121 | 1 << 63 | 1 << 62 | 1 << 57,
        );
        let a = pmull_lo(x01, poly);
        let b = veorq_u8(x01, vextq_u8(a, a, 8));
        let c = pmull_hi(b, poly);
        veorq_u8(x23, veorq_u8(c, b))
    }

    /// Single-block POLYVAL mul (key squaring at init, tail/AAD).
    #[inline]
    #[target_feature(enable = "aes,neon")]
    pub(super) unsafe fn polyval_mul_block(
        a: &[u8; BLOCK_LEN],
        b: &[u8; BLOCK_LEN],
    ) -> [u8; BLOCK_LEN] {
        let av = vld1q_u8(a.as_ptr());
        let bv = vld1q_u8(b.as_ptr());
        let mut acc = acc_zero();
        karatsuba_accumulate(&mut acc, av, bv);
        let r = acc_reduce(acc);
        let mut out = [0u8; BLOCK_LEN];
        vst1q_u8(out.as_mut_ptr(), r);
        out
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes,neon")]
unsafe fn polyval_mul_arm(a: &[u8; BLOCK_LEN], b: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    neon::polyval_mul_block(a, b)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes,neon")]
unsafe fn absorb_8_arm(
    y: &mut [u8; BLOCK_LEN],
    h_powers: &[[u8; BLOCK_LEN]; BATCH_BLOCKS],
    chunk: &[u8; BATCH_LEN],
) {
    use core::arch::aarch64::*;
    let bswap = neon::bswap_indices();
    let state = vld1q_u8(y.as_ptr());
    let h = neon::load_h_powers(h_powers);
    let mut acc = neon::acc_zero();

    for i in 0..BATCH_BLOCKS {
        let x_raw = vld1q_u8(chunk.as_ptr().add(i * BLOCK_LEN));
        let x_rev = vqtbl1q_u8(x_raw, bswap);
        let yi = if i == 0 { veorq_u8(state, x_rev) } else { x_rev };
        neon::karatsuba_accumulate(&mut acc, yi, h[i]);
    }
    let result = neon::acc_reduce(acc);
    vst1q_u8(y.as_mut_ptr(), result);
}

// ============================================================================
// Portable software fallback (compile-time gated; host-only)
// ============================================================================

#[cfg(not(any(
    all(target_arch = "x86_64", target_feature = "pclmulqdq"),
    all(target_arch = "aarch64", target_feature = "aes"),
)))]
fn polyval_mul_soft(a: &[u8; BLOCK_LEN], b: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
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
    for i in (0..128).rev() {
        if (zh >> i) & 1 == 1 {
            zh ^= 1u128 << i;
            let shift = i;
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
    /// version).
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

        let h_keys: &[[u8; 16]] = &[
            [0x00; 16],
            [0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0x42; 16],
            *b"YELLOW SUBMARINE",
            [
                0xee, 0xc0, 0xed, 0x67, 0x6b, 0xa5, 0xee, 0x91,
                0xaf, 0xd3, 0xc4, 0x76, 0x57, 0x71, 0xc4, 0xd4,
            ],
        ];

        let sizes: &[usize] = &[
            0, 16, 32, 48, 64, 80, 96, 112,
            128, 144, 160, 176,
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
}
