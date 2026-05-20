// crates/proto/tls/aes_gcm_fast.rs — 8-block batched, single-pass AES-128-GCM
// with deferred-reduction GHASH.
//
// **Goal**: drop TLS encrypt cycles/byte from ~22 (upstream
// `aes-gcm` baseline, see `record::TLS_ENCRYPT_CYCLES`) toward
// the AES-NI + PCLMUL theoretical floor of ~3 c/B. The
// reduction is what kept us at 22 c/B even after stitched AES;
// `ghash_batch` defers it across 8-block chunks via Gueron 2010
// §4 aggregated Karatsuba.
//
// **Pipeline per chunk** (128 B):
//
//   1. Build 8 CTR blocks, batch-encrypt via AES-NI 8-way.
//   2. XOR with plaintext → ciphertext, in place.
//   3. GHASH-absorb all 8 ciphertext blocks via the batched
//      `GhashState::absorb_8` — 24 PCLMULs + 1 reduction
//      (vs 8 PCLMULs + 8 reductions in the per-block path).
//
// **Correctness**:
//
//   * NIST SP 800-38D §B Test Case 4 — `tests::nist_kat_test_case_4`.
//   * Round-trip + tamper test vs upstream `aes_gcm::Aes128Gcm`
//     across an exhaustive size sweep + AAD variations —
//     `tests::matches_aes_gcm_crate_roundtrip`. Covers the
//     8-block, 16-block, 128-block, and partial-tail paths.
//   * Live integration via `TrafficKey` exercising real TLS
//     records over QEMU x86_64 + HVF aarch64 in
//     `//apps/webserver:test_qemu_x86_64` + `:test_hvf`.
//   * Boot-time KAT in `apps/webserver` exercises a multi-chunk
//     seal so any future bit-order regression in the batched
//     GHASH path surfaces on every boot, not just on the
//     tail-only records that fit in <=127 bytes.

#![allow(unsafe_op_in_unsafe_fn)]

use aes::Aes128;
use aes::cipher::BlockEncrypt;
use aes::cipher::KeyInit as _;
use aes::cipher::generic_array::GenericArray;

use crate::ghash_batch::{BATCH_LEN, BLOCK_LEN as GHASH_BLOCK, GhashKey};

pub const KEY_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// AEAD `open` failure. The only failure mode is "the
/// authentication tag did not match the recomputed tag" — a
/// unit struct (vs an enum or `()`) because constant-time tag
/// compare is the single source of failure for an AES-128-GCM
/// decrypt, and so callers never branch on a variant. Callers
/// either re-key + tear the conn down, or surface it via their
/// own outer error enum (e.g. `RecordError::AeadOpenFailed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadError;

const BLOCK_LEN: usize = 16;
const CHUNK_BLOCKS: usize = 8;
const CHUNK_LEN: usize = BLOCK_LEN * CHUNK_BLOCKS; // 128

const _: () = {
    assert!(BLOCK_LEN == GHASH_BLOCK);
    assert!(CHUNK_LEN == BATCH_LEN);
};

/// Pre-keyed AES-128-GCM context. Holds the AES-128 round-key
/// schedule and the pre-computed H^1..H^8 GHASH table. Reusable
/// across many `seal` / `open` calls — the per-record cost is one
/// nonce-block AES encrypt + the inner 8-batched loop + the final
/// tag XOR.
#[derive(Clone)]
pub struct Aes128GcmFast {
    aes: Aes128,
    ghash_key: GhashKey,
}

impl Aes128GcmFast {
    /// Build a context for a 16-byte key.
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        let aes = Aes128::new(GenericArray::from_slice(key));
        // H = AES_K(0^128).
        let mut h_block: GenericArray<u8, _> = GenericArray::default();
        aes.encrypt_block(&mut h_block);
        let h_bytes: [u8; BLOCK_LEN] = h_block.into();
        let ghash_key = GhashKey::new(&h_bytes);
        Aes128GcmFast { aes, ghash_key }
    }

    /// One-shot seal. `buffer` is plaintext on entry, ciphertext
    /// on exit (same length). Returns the 16-byte tag.
    pub fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buffer: &mut [u8]) -> [u8; TAG_LEN] {
        // J0 + tag mask E_K(J0).
        let mut j0 = [0u8; BLOCK_LEN];
        j0[..NONCE_LEN].copy_from_slice(nonce);
        j0[BLOCK_LEN - 1] = 1;
        let mut mask: GenericArray<u8, _> = GenericArray::clone_from_slice(&j0);
        self.aes.encrypt_block(&mut mask);

        // Initial GHASH state with H folded in; absorb AAD.
        let mut g = self.ghash_key.start();
        g.absorb_padded_slice(aad);

        // Stitched 8-block inner loop: AES-CTR keystream XOR'd
        // into plaintext to produce ciphertext, then GHASH-absorb
        // those same ciphertext blocks *while they're still in
        // registers* — no second pass through the buffer for
        // GHASH. See `stitched_chunk_*` for the per-arch SIMD body.
        let mut counter = increment_be32(&j0);
        let mut ks_buf = [GenericArray::<u8, _>::default(); CHUNK_BLOCKS];
        let mut chunks = buffer.chunks_exact_mut(CHUNK_LEN);
        for chunk in chunks.by_ref() {
            for ks in ks_buf.iter_mut().take(CHUNK_BLOCKS) {
                ks.copy_from_slice(&counter);
                counter = increment_be32(&counter);
            }
            self.aes.encrypt_blocks(&mut ks_buf);

            let ct_chunk: &mut [u8; BATCH_LEN] = (&mut chunk[..BATCH_LEN])
                .try_into()
                .expect("chunks_exact_mut yields BATCH_LEN slices");
            stitched_xor_and_absorb(&mut g, ct_chunk, &ks_buf);
        }

        // Tail: 0..127 bytes. One block at a time.
        let tail = chunks.into_remainder();
        let mut tail_blocks = tail.chunks_exact_mut(BLOCK_LEN);
        for block in tail_blocks.by_ref() {
            let mut ks: GenericArray<u8, _> = GenericArray::default();
            ks.copy_from_slice(&counter);
            self.aes.encrypt_block(&mut ks);
            counter = increment_be32(&counter);
            for j in 0..BLOCK_LEN {
                block[j] ^= ks[j];
            }
            let blk: &[u8; BLOCK_LEN] =
                (&*block).try_into().expect("tail block slice is BLOCK_LEN");
            g.absorb_one(blk);
        }
        let partial = tail_blocks.into_remainder();
        if !partial.is_empty() {
            let n = partial.len();
            let mut ks: GenericArray<u8, _> = GenericArray::default();
            ks.copy_from_slice(&counter);
            self.aes.encrypt_block(&mut ks);
            for j in 0..n {
                partial[j] ^= ks[j];
            }
            g.absorb_partial(partial);
        }

        // Length block, finalize, XOR with tag mask.
        let mut len_block = [0u8; BLOCK_LEN];
        len_block[0..8].copy_from_slice(&(aad.len() as u64).wrapping_mul(8).to_be_bytes());
        len_block[8..16].copy_from_slice(&(buffer.len() as u64).wrapping_mul(8).to_be_bytes());
        g.absorb_one(&len_block);

        let g_out = g.finalize();
        let mut out = [0u8; TAG_LEN];
        for i in 0..TAG_LEN {
            out[i] = g_out[i] ^ mask[i];
        }
        out
    }

    /// Verify-and-decrypt. On success: `buffer` decrypted in
    /// place, returns `Ok(())`. On tag mismatch: `Err(AeadError)`.
    pub fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), AeadError> {
        let mut j0 = [0u8; BLOCK_LEN];
        j0[..NONCE_LEN].copy_from_slice(nonce);
        j0[BLOCK_LEN - 1] = 1;
        let mut mask: GenericArray<u8, _> = GenericArray::clone_from_slice(&j0);
        self.aes.encrypt_block(&mut mask);

        let mut g = self.ghash_key.start();
        g.absorb_padded_slice(aad);

        // Decrypt path: GHASH the ciphertext BEFORE the XOR
        // (otherwise we'd be authing plaintext). Batched-absorb 8
        // ciphertext blocks per iteration, then decrypt those 8.
        let mut counter = increment_be32(&j0);
        let mut ks_buf = [GenericArray::<u8, _>::default(); CHUNK_BLOCKS];
        let buf_len = buffer.len();
        let mut chunks = buffer.chunks_exact_mut(CHUNK_LEN);
        for chunk in chunks.by_ref() {
            // GHASH ciphertext first — batched.
            let ct_chunk: &[u8; BATCH_LEN] = chunk[..BATCH_LEN]
                .try_into()
                .expect("chunks_exact_mut yields BATCH_LEN slices");
            g.absorb_8(ct_chunk);

            // Then decrypt.
            for ks in ks_buf.iter_mut().take(CHUNK_BLOCKS) {
                ks.copy_from_slice(&counter);
                counter = increment_be32(&counter);
            }
            self.aes.encrypt_blocks(&mut ks_buf);
            for i in 0..CHUNK_BLOCKS {
                let block = &mut chunk[i * BLOCK_LEN..(i + 1) * BLOCK_LEN];
                for j in 0..BLOCK_LEN {
                    block[j] ^= ks_buf[i][j];
                }
            }
        }

        let tail = chunks.into_remainder();
        let mut tail_blocks = tail.chunks_exact_mut(BLOCK_LEN);
        for block in tail_blocks.by_ref() {
            let snapshot: [u8; BLOCK_LEN] =
                (&*block).try_into().expect("tail block slice is BLOCK_LEN");
            g.absorb_one(&snapshot);
            let mut ks: GenericArray<u8, _> = GenericArray::default();
            ks.copy_from_slice(&counter);
            self.aes.encrypt_block(&mut ks);
            counter = increment_be32(&counter);
            for j in 0..BLOCK_LEN {
                block[j] ^= ks[j];
            }
        }
        let partial = tail_blocks.into_remainder();
        if !partial.is_empty() {
            let n = partial.len();
            g.absorb_partial(partial);
            let mut ks: GenericArray<u8, _> = GenericArray::default();
            ks.copy_from_slice(&counter);
            self.aes.encrypt_block(&mut ks);
            for j in 0..n {
                partial[j] ^= ks[j];
            }
        }

        let mut len_block = [0u8; BLOCK_LEN];
        len_block[0..8].copy_from_slice(&(aad.len() as u64).wrapping_mul(8).to_be_bytes());
        len_block[8..16].copy_from_slice(&(buf_len as u64).wrapping_mul(8).to_be_bytes());
        g.absorb_one(&len_block);

        let g_out = g.finalize();
        let mut computed = [0u8; TAG_LEN];
        for i in 0..TAG_LEN {
            computed[i] = g_out[i] ^ mask[i];
        }
        if ct_eq_tag(&computed, tag) {
            Ok(())
        } else {
            Err(AeadError)
        }
    }

    /// Fused scatter-gather seal. Source plaintext from a chain
    /// of byte slices, ciphertext lands in `dst`, tag returned.
    pub fn seal_chain<'a, I>(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        src_parts: I,
        dst: &mut [u8],
    ) -> [u8; TAG_LEN]
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut cursor = 0usize;
        for src in src_parts {
            let n = src.len();
            if n == 0 {
                continue;
            }
            dst[cursor..cursor + n].copy_from_slice(src);
            cursor += n;
        }
        self.seal(nonce, aad, &mut dst[..cursor])
    }
}

#[inline(always)]
fn ct_eq_tag(a: &[u8; TAG_LEN], b: &[u8; TAG_LEN]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..TAG_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[inline(always)]
fn increment_be32(counter: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    let mut out = *counter;
    let c = u32::from_be_bytes([out[12], out[13], out[14], out[15]]);
    let be = c.wrapping_add(1).to_be_bytes();
    out[12] = be[0];
    out[13] = be[1];
    out[14] = be[2];
    out[15] = be[3];
    out
}

// ============================================================================
// Stitched AES-CTR XOR + batched GHASH absorb
// ============================================================================
//
// Per 128-byte chunk: each ciphertext block stays in a SIMD
// register from the moment AES-CTR XOR produces it through the
// PCLMUL/PMULL Karatsuba accumulate — only writing to memory
// once. Reduces the chunk's L1 traffic from 3 read+writes (PT
// in, CT out, CT in for GHASH) to 2 (PT in, CT out).
//
// The Karatsuba math lives in `ghash_batch::{xmm,neon}`; this
// just orchestrates the per-arch SIMD load → XOR → store →
// accumulate sequence with the H^k powers loaded once per chunk.

#[inline]
fn stitched_xor_and_absorb(
    g: &mut crate::ghash_batch::GhashState<'_>,
    chunk: &mut [u8; CHUNK_LEN],
    ks_buf: &[GenericArray<u8, aes::cipher::consts::U16>; CHUNK_BLOCKS],
) {
    #[cfg(all(target_arch = "x86_64", target_feature = "pclmulqdq"))]
    unsafe {
        stitched_chunk_x86(g, chunk, ks_buf);
        return;
    }
    #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
    unsafe {
        stitched_chunk_arm(g, chunk, ks_buf);
        return;
    }
    #[allow(unreachable_code)]
    {
        // Portable fallback: XOR pass, then batched absorb.
        // Same memory traffic as the pre-stitched code; only
        // used on hosts without PCLMUL/PMULL (e.g. `cargo test`
        // under emulation). Kept for compile-time portability.
        for i in 0..CHUNK_BLOCKS {
            let block = &mut chunk[i * BLOCK_LEN..(i + 1) * BLOCK_LEN];
            for j in 0..BLOCK_LEN {
                block[j] ^= ks_buf[i][j];
            }
        }
        g.absorb_8(chunk);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2,ssse3,pclmulqdq")]
unsafe fn stitched_chunk_x86(
    g: &mut crate::ghash_batch::GhashState<'_>,
    chunk: &mut [u8; CHUNK_LEN],
    ks_buf: &[GenericArray<u8, aes::cipher::consts::U16>; CHUNK_BLOCKS],
) {
    use crate::ghash_batch::xmm;
    use core::arch::x86_64::*;

    let bswap = xmm::bswap_mask();
    let state_polyval = g.polyval_state();
    let state = _mm_loadu_si128(state_polyval.as_ptr() as *const __m128i);
    let h = xmm::load_h_powers(g.key().h_powers());
    let mut acc = xmm::acc_zero();

    for i in 0..CHUNK_BLOCKS {
        // Load plaintext + keystream into registers; XOR to get CT.
        let pt = _mm_loadu_si128(chunk.as_ptr().add(i * BLOCK_LEN) as *const __m128i);
        let ks = _mm_loadu_si128(ks_buf[i].as_ptr() as *const __m128i);
        let ct = _mm_xor_si128(pt, ks);
        // Write CT back to the buffer (the only memory traffic
        // we owe the caller — plaintext-to-ciphertext output).
        _mm_storeu_si128(chunk.as_mut_ptr().add(i * BLOCK_LEN) as *mut __m128i, ct);
        // GHASH-absorb the same register-resident CT (no reload).
        let ct_rev = _mm_shuffle_epi8(ct, bswap);
        let yi = if i == 0 {
            _mm_xor_si128(state, ct_rev)
        } else {
            ct_rev
        };
        xmm::karatsuba_accumulate(&mut acc, yi, h[i]);
    }

    let new_state = xmm::acc_reduce(acc);
    let mut out = [0u8; BLOCK_LEN];
    _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, new_state);
    g.set_polyval_state(out);
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes,neon")]
unsafe fn stitched_chunk_arm(
    g: &mut crate::ghash_batch::GhashState<'_>,
    chunk: &mut [u8; CHUNK_LEN],
    ks_buf: &[GenericArray<u8, aes::cipher::consts::U16>; CHUNK_BLOCKS],
) {
    use crate::ghash_batch::neon;
    use core::arch::aarch64::*;

    let bswap = neon::bswap_indices();
    let state_polyval = g.polyval_state();
    let state = vld1q_u8(state_polyval.as_ptr());
    let h = neon::load_h_powers(g.key().h_powers());
    let mut acc = neon::acc_zero();

    for i in 0..CHUNK_BLOCKS {
        let pt = vld1q_u8(chunk.as_ptr().add(i * BLOCK_LEN));
        let ks = vld1q_u8(ks_buf[i].as_ptr());
        let ct = veorq_u8(pt, ks);
        vst1q_u8(chunk.as_mut_ptr().add(i * BLOCK_LEN), ct);
        let ct_rev = vqtbl1q_u8(ct, bswap);
        let yi = if i == 0 {
            veorq_u8(state, ct_rev)
        } else {
            ct_rev
        };
        neon::karatsuba_accumulate(&mut acc, yi, h[i]);
    }

    let new_state = neon::acc_reduce(acc);
    let mut out = [0u8; BLOCK_LEN];
    vst1q_u8(out.as_mut_ptr(), new_state);
    g.set_polyval_state(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_kat_test_case_4() {
        let key: [u8; 16] = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08,
        ];
        let nonce: [u8; 12] = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let aad: [u8; 20] = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
            0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2,
        ];
        let plaintext: [u8; 60] = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39,
        ];
        let expected_ct: [u8; 60] = [
            0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0,
            0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23,
            0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f,
            0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
            0x3d, 0x58, 0xe0, 0x91,
        ];
        let expected_tag: [u8; 16] = [
            0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12,
            0x1a, 0x47,
        ];

        let ctx = Aes128GcmFast::new(&key);
        let mut buf = plaintext;
        let tag = ctx.seal(&nonce, &aad, &mut buf);
        assert_eq!(buf, expected_ct);
        assert_eq!(tag, expected_tag);

        ctx.open(&nonce, &aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn matches_aes_gcm_crate_roundtrip() {
        use aes_gcm::Aes128Gcm;
        use aes_gcm::aead::AeadInPlace;
        use aes_gcm::aead::KeyInit as KI;

        let key = [0x42u8; 16];
        let nonce = [0x17u8; 12];
        let fast = Aes128GcmFast::new(&key);
        let slow = Aes128Gcm::new(GenericArray::from_slice(&key));

        // Cover: 0, partial-block-only, exactly-block, full
        // 8-block chunk (128 B), multi-chunk, multi-chunk +
        // partial tail. With and without AAD of various lengths.
        let sizes = [
            0usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 100, 127, 128, 129, 200, 256, 257, 511, 512,
            1024, 4096, 9000, 16383,
        ];
        let aads: &[&[u8]] = &[
            b"",
            b"a",
            b"sixteen bytes!!!",
            b"a longer aad spanning multiple blocks more than once over",
        ];

        for &size in &sizes {
            let plaintext: alloc::vec::Vec<u8> =
                (0..size).map(|i| (i as u8).wrapping_mul(31)).collect();

            for aad in aads.iter() {
                let mut fast_buf = plaintext.clone();
                let fast_tag = fast.seal(&nonce, aad, &mut fast_buf);

                let mut slow_buf = plaintext.clone();
                let slow_tag = slow
                    .encrypt_in_place_detached(GenericArray::from_slice(&nonce), aad, &mut slow_buf)
                    .unwrap();

                assert_eq!(
                    fast_buf,
                    slow_buf,
                    "ciphertext mismatch size={} aad_len={}",
                    size,
                    aad.len()
                );
                assert_eq!(
                    &fast_tag,
                    slow_tag.as_slice(),
                    "tag mismatch size={} aad_len={}",
                    size,
                    aad.len()
                );

                // Round-trip.
                let mut decrypted = fast_buf.clone();
                fast.open(&nonce, aad, &mut decrypted, &fast_tag)
                    .expect("tag should verify on round-trip");
                assert_eq!(decrypted, plaintext, "decrypt round-trip size={}", size);

                // Tamper.
                if !plaintext.is_empty() {
                    let mut tampered = fast_buf.clone();
                    tampered[0] ^= 1;
                    assert!(
                        fast.open(&nonce, aad, &mut tampered, &fast_tag).is_err(),
                        "tamper not detected size={}",
                        size
                    );
                }
                let mut bad_tag = fast_tag;
                bad_tag[0] ^= 1;
                let mut buf = fast_buf.clone();
                assert!(
                    fast.open(&nonce, aad, &mut buf, &bad_tag).is_err(),
                    "bad tag not detected size={}",
                    size
                );
            }
        }
    }
}
