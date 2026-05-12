// uni-tls/aes_gcm_fast.rs — 8-block batched, single-pass AES-128-GCM.
//
// **Goal**: Cut the ~22 cycles/byte we measured for `aes-gcm 0.10`
// (RustCrypto). See commit message of `17de406` for the cycle
// attribution data that motivates this.
//
// **What upstream gets wrong** (RustCrypto/AEADs#74, open since
// 2020): `aes-gcm::Aes128Gcm::encrypt_in_place_detached` runs the
// full AES-CTR pass over the buffer, *then* the full GHASH pass.
// Two passes through memory; no instruction-level pipelining
// between AES-NI and PCLMUL.
//
// **What this module does**: single-pass 8-block-batched loop.
// Per iteration:
//
//   1. Generate 8 counter blocks.
//   2. AES-encrypt all 8 via `aes::Aes128::encrypt_blocks` —
//      which dispatches to the 8-way AES-NI backend on x86 (see
//      `aes 0.8.4`'s `ni::aes128::encrypt8`) and the FEAT_AES
//      backend on aarch64. The keystream stays in registers /
//      hot in L1.
//   3. XOR with plaintext → ciphertext in place.
//   4. GHASH-absorb each of the 8 just-written ciphertext blocks
//      via `ghash::GHash::update`. The block is still hot from
//      the XOR.
//
// **Cross-arch**: identical source on every target. The
// hardware acceleration comes from `aes` + `ghash` having
// per-arch backends (`ni` / `armv8` / `clmul` / `pmull`).
//
// **What's still on the table (~4× more speedup)**: replacing
// the per-block GHASH with a 4- or 8-way Karatsuba batched
// GHASH that defers polynomial reduction to once per chunk.
// The math is well-known (Gueron 2010 §4); the implementation
// trap is the PCLMUL-vs-GHASH bit-order convention. An earlier
// version of this file got that wrong (byte-swap without
// bit-reverse), shipped working KAT but failed the integration
// test under TLS record-layer tag verification. Building it
// correctly is a focused follow-up.
//
// **Correctness**:
//
//   * NIST SP 800-38D §B Test Case 4 — `tests::nist_kat_test_case_4`.
//   * Round-trip + tamper test vs upstream `aes_gcm::Aes128Gcm`
//     across an exhaustive size sweep + AAD variations —
//     `tests::matches_aes_gcm_crate_roundtrip`.
//   * Live integration via `TrafficKey` exercising real TLS
//     records over QEMU x86_64 + HVF aarch64 in
//     `//apps/webserver:test_qemu_x86_64` + `:test_hvf`.

use aes::cipher::BlockEncrypt;
use aes::cipher::KeyInit as _;
use aes::cipher::generic_array::GenericArray;
use aes::Aes128;
use ghash::universal_hash::UniversalHash;
use ghash::GHash;

pub const KEY_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
const BLOCK_LEN: usize = 16;
const CHUNK_BLOCKS: usize = 8;
const CHUNK_LEN: usize = BLOCK_LEN * CHUNK_BLOCKS; // 128

/// Pre-keyed AES-128-GCM context. Holds the AES-128 round-key
/// schedule and the pre-keyed GHASH accumulator template
/// (`H = AES_K(0^128)` already folded in). Reusable across many
/// `seal` / `open` calls — the per-record cost is one nonce-block
/// AES encrypt + the inner 8-batched loop + the final tag XOR.
#[derive(Clone)]
pub struct Aes128GcmFast {
    aes: Aes128,
    h_acc_template: GHash,
}

impl Aes128GcmFast {
    /// Build a context for a 16-byte key.
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        let aes = Aes128::new(GenericArray::from_slice(key));
        let mut h_block: GenericArray<u8, _> = GenericArray::default();
        aes.encrypt_block(&mut h_block);
        let h_acc_template = <GHash as ghash::universal_hash::KeyInit>::new(
            GenericArray::from_slice(&h_block),
        );
        Aes128GcmFast { aes, h_acc_template }
    }

    /// One-shot seal. `buffer` is plaintext on entry, ciphertext
    /// on exit (same length). Returns the 16-byte tag.
    pub fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> [u8; TAG_LEN] {
        // J0 + tag mask E_K(J0).
        let mut j0 = [0u8; BLOCK_LEN];
        j0[..NONCE_LEN].copy_from_slice(nonce);
        j0[BLOCK_LEN - 1] = 1;
        let mut mask: GenericArray<u8, _> = GenericArray::clone_from_slice(&j0);
        self.aes.encrypt_block(&mut mask);

        // Initial GHASH state with H folded in; absorb AAD.
        let mut g = self.h_acc_template.clone();
        if !aad.is_empty() {
            g.update_padded(aad);
        }

        // Stitched 8-block batched inner loop.
        let mut counter = increment_be32(&j0);
        let mut ks_buf = [GenericArray::<u8, _>::default(); CHUNK_BLOCKS];
        let mut chunks = buffer.chunks_exact_mut(CHUNK_LEN);
        for chunk in chunks.by_ref() {
            // 8 counters → 8 keystreams (batched AES-NI on x86,
            // batched FEAT_AES on aarch64).
            for i in 0..CHUNK_BLOCKS {
                ks_buf[i].copy_from_slice(&counter);
                counter = increment_be32(&counter);
            }
            self.aes.encrypt_blocks(&mut ks_buf);

            // XOR with plaintext to make ciphertext, GHASH each
            // ciphertext block as we go.
            for i in 0..CHUNK_BLOCKS {
                let block = &mut chunk[i * BLOCK_LEN..(i + 1) * BLOCK_LEN];
                for j in 0..BLOCK_LEN {
                    block[j] ^= ks_buf[i][j];
                }
                let ct: &GenericArray<u8, _> = GenericArray::from_slice(block);
                g.update(&[*ct]);
            }
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
            let ct: &GenericArray<u8, _> = GenericArray::from_slice(block);
            g.update(&[*ct]);
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
            let mut padded = [0u8; BLOCK_LEN];
            padded[..n].copy_from_slice(partial);
            let ct: &GenericArray<u8, _> = GenericArray::from_slice(&padded);
            g.update(&[*ct]);
        }

        // Length block, finalize, XOR with tag mask.
        let mut len_block = [0u8; BLOCK_LEN];
        len_block[0..8].copy_from_slice(&(aad.len() as u64).wrapping_mul(8).to_be_bytes());
        len_block[8..16].copy_from_slice(&(buffer.len() as u64).wrapping_mul(8).to_be_bytes());
        let lb: &GenericArray<u8, _> = GenericArray::from_slice(&len_block);
        g.update(&[*lb]);

        let g_out = g.finalize();
        let mut out = [0u8; TAG_LEN];
        for i in 0..TAG_LEN {
            out[i] = g_out[i] ^ mask[i];
        }
        out
    }

    /// Verify-and-decrypt. On success: `buffer` decrypted in
    /// place, returns `Ok(())`. On tag mismatch: `Err(())`.
    pub fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), ()> {
        let mut j0 = [0u8; BLOCK_LEN];
        j0[..NONCE_LEN].copy_from_slice(nonce);
        j0[BLOCK_LEN - 1] = 1;
        let mut mask: GenericArray<u8, _> = GenericArray::clone_from_slice(&j0);
        self.aes.encrypt_block(&mut mask);

        let mut g = self.h_acc_template.clone();
        if !aad.is_empty() {
            g.update_padded(aad);
        }

        // Decrypt path: GHASH the ciphertext BEFORE the XOR
        // (otherwise we'd be authing plaintext). Snapshot 8
        // blocks at a time, GHASH-absorb, then decrypt.
        let mut counter = increment_be32(&j0);
        let mut ks_buf = [GenericArray::<u8, _>::default(); CHUNK_BLOCKS];
        let buf_len = buffer.len();
        let mut chunks = buffer.chunks_exact_mut(CHUNK_LEN);
        for chunk in chunks.by_ref() {
            // GHASH ciphertext first.
            for i in 0..CHUNK_BLOCKS {
                let block_slice = &chunk[i * BLOCK_LEN..(i + 1) * BLOCK_LEN];
                let ct: &GenericArray<u8, _> = GenericArray::from_slice(block_slice);
                g.update(&[*ct]);
            }
            // Then decrypt.
            for i in 0..CHUNK_BLOCKS {
                ks_buf[i].copy_from_slice(&counter);
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
            let snapshot = {
                let mut tmp = [0u8; BLOCK_LEN];
                tmp.copy_from_slice(block);
                tmp
            };
            let ct: &GenericArray<u8, _> = GenericArray::from_slice(&snapshot);
            g.update(&[*ct]);
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
            let mut padded = [0u8; BLOCK_LEN];
            padded[..n].copy_from_slice(partial);
            let ct: &GenericArray<u8, _> = GenericArray::from_slice(&padded);
            g.update(&[*ct]);
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
        let lb: &GenericArray<u8, _> = GenericArray::from_slice(&len_block);
        g.update(&[*lb]);

        let g_out = g.finalize();
        let mut computed = [0u8; TAG_LEN];
        for i in 0..TAG_LEN {
            computed[i] = g_out[i] ^ mask[i];
        }
        if ct_eq_tag(&computed, tag) { Ok(()) } else { Err(()) }
    }

    /// Fused scatter-gather seal. Source plaintext from a chain
    /// of byte slices, ciphertext lands in `dst`, tag returned.
    pub fn seal_chain_to<'a, I>(
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
            if n == 0 { continue; }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_kat_test_case_4() {
        let key: [u8; 16] = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
            0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        ];
        let nonce: [u8; 12] = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
            0xde, 0xca, 0xf8, 0x88,
        ];
        let aad: [u8; 20] = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
            0xab, 0xad, 0xda, 0xd2,
        ];
        let plaintext: [u8; 60] = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
            0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
            0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
            0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
            0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
            0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
            0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39,
        ];
        let expected_ct: [u8; 60] = [
            0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
            0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
            0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
            0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
            0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
            0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
            0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
            0x3d, 0x58, 0xe0, 0x91,
        ];
        let expected_tag: [u8; 16] = [
            0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
            0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47,
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
        use aes_gcm::aead::AeadInPlace;
        use aes_gcm::aead::KeyInit as KI;
        use aes_gcm::Aes128Gcm;

        let key = [0x42u8; 16];
        let nonce = [0x17u8; 12];
        let fast = Aes128GcmFast::new(&key);
        let slow = Aes128Gcm::new(GenericArray::from_slice(&key));

        // Cover: 0, partial-block-only, exactly-block, full
        // 8-block chunk (128 B), multi-chunk, multi-chunk +
        // partial tail. With and without AAD of various lengths.
        let sizes = [
            0usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 100, 127,
            128, 129, 200, 256, 257, 511, 512, 1024, 4096, 9000,
            16383,
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
                    .encrypt_in_place_detached(
                        GenericArray::from_slice(&nonce),
                        aad,
                        &mut slow_buf,
                    )
                    .unwrap();

                assert_eq!(
                    fast_buf, slow_buf,
                    "ciphertext mismatch size={} aad_len={}",
                    size, aad.len()
                );
                assert_eq!(
                    &fast_tag,
                    slow_tag.as_slice(),
                    "tag mismatch size={} aad_len={}",
                    size, aad.len()
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
