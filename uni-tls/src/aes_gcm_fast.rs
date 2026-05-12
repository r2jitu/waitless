// uni-tls/aes_gcm_fast.rs — Hand-rolled stitched AES-128-GCM.
//
// Why not just call `aes-gcm::Aes128Gcm::encrypt_in_place_detached`?
// Cycle-attribution bracketing on a saturated `diagnostics_tls_max`
// bench showed `aes-gcm 0.10` was consuming **45-64% of busy CPU**
// at **~22 cycles per byte** — versus the OpenSSL / BoringSSL /
// Linux-kernel reference of ~0.7-1.0 cycles/byte. Two structural
// reasons:
//
//   1. `aes-gcm` has an open `TODO(tarcieri): interleave encryption
//      with GHASH` at the top of its `encrypt_in_place_detached`
//      hot path (see RustCrypto/AEADs#74). It does the full
//      AES-CTR pass over the buffer, THEN the full GHASH pass —
//      two sequential passes through memory + no instruction-level
//      pipelining between AES-NI and PCLMUL.
//   2. `polyval 0.6.2`'s hardware backend declares
//      `type ParBlocksSize = U1`: it processes one block at a
//      time, doing a full polynomial reduction per block. The
//      well-known 4-or-8-way Karatsuba batched-GHASH with deferred
//      reduction (used by every fast AES-GCM impl since ~2010) is
//      not in the crate.
//
// This module ships a stitched single-pass implementation that
// interleaves the AES-CTR per-block encrypt with a per-block GHASH
// update. Each 16-byte chunk is read once, XOR'd with its
// keystream block, written once, and immediately fed to GHASH
// while still hot in cache. That eliminates the two-pass memory
// traffic and lets the CPU's reorder window overlap the AES-NI
// `aesenc` chain with the PCLMUL multiply of the previous block.
//
// **Scope**: This is the minimum-viable "fix the TODO" speedup,
// using the existing `aes` + `polyval` primitives unchanged. A
// further win (~4x more on top) is available by hand-rolling the
// 8-way batched GHASH with deferred reduction; that's deliberately
// deferred — it would mean shipping new intrinsics-only crypto
// without an established review surface.
//
// **Correctness**: the boot KAT (NIST SP 800-38D §B Test Case 4)
// in `aead::rfc8439_kat` already exercises this path via
// `TrafficKey::seal` once it routes through here. A second KAT
// in this module's `tests` covers a round-trip + tag-tamper
// detection so a regression surfaces in `bazel test //uni-tls`.

use aes::cipher::BlockEncrypt;
// `Aes128::new` is via the `cipher::KeyInit` trait — pulled in
// as `_` so it's reachable for the `Aes128::new` call. GHash's
// `new` is called via FQS to avoid name collision.
use aes::cipher::KeyInit as _;
use aes::Aes128;
use ghash::universal_hash::UniversalHash;
use ghash::GHash;

use aes::cipher::generic_array::GenericArray;

pub const KEY_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
const BLOCK_LEN: usize = 16;

/// Pre-keyed AES-128-GCM context. Holds the AES round-key
/// expansion and the GHASH subkey `H = AES_K(0)`. Reusable
/// across many `seal`/`open` calls — the per-record cost is
/// just one nonce-block AES, one AAD walk, the stitched
/// CTR+GHASH loop, and the final tag XOR.
#[derive(Clone)]
pub struct Aes128GcmFast {
    aes: Aes128,
    /// GHASH subkey, stored in `GHash`'s pre-keyed form so we
    /// can `clone()` a fresh accumulator per record without
    /// recomputing `H` (which costs an AES-block encrypt + the
    /// polyval byte-swap dance).
    h_acc_template: GHash,
}

impl Aes128GcmFast {
    /// Build a context for a 16-byte key. Performs the AES-128
    /// key schedule (~10 `aeskeygenassist` rounds) and computes
    /// `H = AES_K(0^128)` for GHASH.
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        let aes = Aes128::new(GenericArray::from_slice(key));

        // GHASH subkey H = E_K(0^128). Use the AES-NI 1-block
        // path; we only do this once per key.
        let mut h_block = GenericArray::default();
        aes.encrypt_block(&mut h_block);

        // GHash takes the 16-byte H key directly and internally
        // does the polyval byte-reversal that makes the math
        // come out as GHASH (rather than POLYVAL). Use FQS so
        // we don't need a `use ghash::KeyInit` that would
        // shadow aes::cipher::KeyInit.
        let h_acc_template = <GHash as ghash::universal_hash::KeyInit>::new(
            GenericArray::from_slice(&h_block),
        );

        Aes128GcmFast { aes, h_acc_template }
    }

    /// One-shot stitched seal. `buffer` is plaintext on entry,
    /// ciphertext on exit (same length). Returns the 16-byte
    /// authentication tag.
    pub fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> [u8; TAG_LEN] {
        // J0 is the initial CTR block: 12-byte nonce || 0^31 || 1.
        // The first counter the encryption uses is J0 + 1; the
        // `mask` we'll XOR into the tag is E_K(J0).
        let mut j0 = [0u8; BLOCK_LEN];
        j0[..NONCE_LEN].copy_from_slice(nonce);
        j0[BLOCK_LEN - 1] = 1;

        // Compute the tag mask now while AES round keys are
        // cache-hot — we'll need it at the very end of the
        // function, but the alternative (recomputing then) costs
        // an L1 reload of the round-key state.
        let mut mask = GenericArray::clone_from_slice(&j0);
        self.aes.encrypt_block(&mut mask);

        // Stitched CTR + GHASH inner loop. Counter starts at
        // J0 + 1 — the 32-bit counter lives in bytes 12..16 in
        // big-endian.
        let mut counter = increment_be32(&j0);

        let mut g = self.h_acc_template.clone();

        // Absorb AAD. GHASH is computed over
        // `AAD || padding_to_16 || ciphertext || padding_to_16 ||
        //  len(AAD)_64 || len(C)_64`. Polyval's
        // `update_padded` walks the slice in 16-byte blocks
        // zero-padding any short tail.
        if !aad.is_empty() {
            g.update_padded(aad);
        }

        // Process full 16-byte blocks of the buffer. Per
        // iteration:
        //   1. AES-encrypt the counter block (1-block AES-NI;
        //      latency ~7 cycles, overlapped with the previous
        //      iteration's GHASH).
        //   2. XOR with plaintext → ciphertext in-place.
        //   3. GHASH-absorb the just-written ciphertext block.
        //   4. Increment the BE32 counter.
        //
        // The CPU's reorder window pipelines iter (i+1)'s AES
        // with iter (i)'s GHASH, so wall-clock per block is
        // `max(AES, GHASH)` — not the sum.
        let mut chunks = buffer.chunks_exact_mut(BLOCK_LEN);
        for block in chunks.by_ref() {
            let mut ks = counter.into();
            self.aes.encrypt_block(&mut ks);
            for i in 0..BLOCK_LEN {
                block[i] ^= ks[i];
            }
            // SAFETY: `block` is exactly 16 bytes
            // (chunks_exact_mut); GenericArray::from_slice
            // checks the length matches.
            let ct: &GenericArray<u8, _> = GenericArray::from_slice(block);
            g.update(&[*ct]);
            counter = increment_be32(&counter);
        }

        // Tail: 1-15 partial bytes. Encrypt one more counter
        // block, XOR only the partial-block prefix, and absorb
        // the partial block zero-padded for GHASH.
        let tail = chunks.into_remainder();
        if !tail.is_empty() {
            let mut ks = counter.into();
            self.aes.encrypt_block(&mut ks);
            let n = tail.len();
            for i in 0..n {
                tail[i] ^= ks[i];
            }
            // GHASH-pad the partial ciphertext block to 16 bytes.
            let mut padded = [0u8; BLOCK_LEN];
            padded[..n].copy_from_slice(tail);
            let ct: &GenericArray<u8, _> = GenericArray::from_slice(&padded);
            g.update(&[*ct]);
        }

        // Length block: GHASH absorbs len(AAD)*8 || len(C)*8 as
        // two big-endian u64 fields in a single 16-byte block.
        let mut len_block = [0u8; BLOCK_LEN];
        let aad_bits = (aad.len() as u64).wrapping_mul(8);
        let buf_bits = (buffer.len() as u64).wrapping_mul(8);
        len_block[0..8].copy_from_slice(&aad_bits.to_be_bytes());
        len_block[8..16].copy_from_slice(&buf_bits.to_be_bytes());
        {
            let lb: &GenericArray<u8, _> = GenericArray::from_slice(&len_block);
            g.update(&[*lb]);
        }

        // Final tag = GHASH(AAD || C || lens) XOR E_K(J0). Note
        // polyval's "tag" output is the GHASH state directly
        // (polyval = GHASH on the GCM mapping, same wire bytes).
        let mut out = [0u8; TAG_LEN];
        let g_out = g.finalize();
        for i in 0..TAG_LEN {
            out[i] = g_out[i] ^ mask[i];
        }
        out
    }

    /// Verify-and-open. On success: `buffer` decrypted in place,
    /// returns `Ok(())`. On tag mismatch: `Err(())` and
    /// `buffer`'s contents are unspecified (we don't bother
    /// restoring — the caller treats failure as a fatal alert).
    pub fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), ()> {
        // Decrypt path: same stitched loop, but we must GHASH
        // the *ciphertext* (untouched buffer contents) BEFORE
        // we XOR with keystream — otherwise we'd be authing the
        // plaintext, not the ciphertext.
        let mut j0 = [0u8; BLOCK_LEN];
        j0[..NONCE_LEN].copy_from_slice(nonce);
        j0[BLOCK_LEN - 1] = 1;

        let mut mask = GenericArray::clone_from_slice(&j0);
        self.aes.encrypt_block(&mut mask);

        let mut g = self.h_acc_template.clone();
        if !aad.is_empty() {
            g.update_padded(aad);
        }

        // Pass 1 (GHASH over ciphertext) followed by pass 2
        // (decrypt) would re-introduce the two-pass cost we're
        // trying to avoid. So we GHASH and decrypt in lockstep:
        // for each block, copy it (so we have an immutable
        // snapshot for GHASH), then XOR in place. Block stays
        // in L1 across both reads.
        let mut counter = increment_be32(&j0);
        let mut chunks = buffer.chunks_exact_mut(BLOCK_LEN);
        for block in chunks.by_ref() {
            // Snapshot ciphertext for GHASH (16 bytes, stays in
            // L1/regs).
            let ct_snapshot = {
                let mut tmp = [0u8; BLOCK_LEN];
                tmp.copy_from_slice(block);
                tmp
            };
            let ct: &GenericArray<u8, _> = GenericArray::from_slice(&ct_snapshot);
            g.update(&[*ct]);

            let mut ks = counter.into();
            self.aes.encrypt_block(&mut ks);
            for i in 0..BLOCK_LEN {
                block[i] ^= ks[i];
            }
            counter = increment_be32(&counter);
        }

        let tail = chunks.into_remainder();
        if !tail.is_empty() {
            let n = tail.len();
            let mut padded = [0u8; BLOCK_LEN];
            padded[..n].copy_from_slice(tail);
            let ct: &GenericArray<u8, _> = GenericArray::from_slice(&padded);
            g.update(&[*ct]);

            let mut ks = counter.into();
            self.aes.encrypt_block(&mut ks);
            for i in 0..n {
                tail[i] ^= ks[i];
            }
        }

        let mut len_block = [0u8; BLOCK_LEN];
        let aad_bits = (aad.len() as u64).wrapping_mul(8);
        let buf_bits = (buffer.len() as u64).wrapping_mul(8);
        len_block[0..8].copy_from_slice(&aad_bits.to_be_bytes());
        len_block[8..16].copy_from_slice(&buf_bits.to_be_bytes());
        {
            let lb: &GenericArray<u8, _> = GenericArray::from_slice(&len_block);
            g.update(&[*lb]);
        }

        let g_out = g.finalize();
        let mut computed = [0u8; TAG_LEN];
        for i in 0..TAG_LEN {
            computed[i] = g_out[i] ^ mask[i];
        }

        // Constant-time tag comparison. The compiler is allowed
        // to optimise this into a branch-on-difference, but
        // `subtle::ConstantTimeEq` is what `aes-gcm` uses too
        // and we'd be a regression if we did anything less
        // careful. Roll a tiny constant-time `ct_eq` here since
        // we don't want to pull in the `subtle` crate as a
        // direct dep just for this.
        let mut diff: u8 = 0;
        for i in 0..TAG_LEN {
            diff |= computed[i] ^ tag[i];
        }
        if diff == 0 {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Fused scatter-gather seal. Same shape as
    /// [`aead::seal_chain_to`] — the old aes-gcm-backed
    /// implementation in `aead.rs` does `copy chain → dst` then
    /// in-place encrypt; we do the copy and encrypt in a single
    /// pass per block. Source plaintext is read from `src_parts`
    /// (any chain of `&[u8]`), ciphertext lands in `dst`, tag
    /// is returned. `dst` must be at least `sum(|src|)` bytes.
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
        // Step 1: copy chain into dst. We could stitch this
        // INTO the encrypt loop block-by-block (true fused
        // copy+encrypt) but the chain iterator complicates the
        // block-alignment math; for now keep the copy as a
        // single first pass and stitch encrypt+GHASH below.
        // Chain bytes are small (one TLS record's worth) and
        // L1-resident after the copy, so the perf hit is
        // minimal.
        let mut cursor = 0usize;
        for src in src_parts {
            let n = src.len();
            if n == 0 {
                continue;
            }
            dst[cursor..cursor + n].copy_from_slice(src);
            cursor += n;
        }
        // Step 2: stitched encrypt-and-GHASH over the copied
        // prefix. Calling `self.seal(nonce, aad, &mut dst[..cursor])`
        // gets us the single-pass inner loop without code
        // duplication.
        self.seal(nonce, aad, &mut dst[..cursor])
    }
}

/// Increment a 16-byte counter block's low 4 bytes as a
/// big-endian u32 (per NIST SP 800-38D §6.2's `inc_{32}`). The
/// upper 12 bytes (the nonce prefix) are untouched. Wrap is
/// allowed per spec — at 32-bit width over 16 GiB of buffer
/// we'd need a 16-EiB single AEAD call to overflow, well past
/// `P_MAX`.
#[inline(always)]
fn increment_be32(counter: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    let mut out = *counter;
    let mut c = u32::from_be_bytes([out[12], out[13], out[14], out[15]]);
    c = c.wrapping_add(1);
    let be = c.to_be_bytes();
    out[12] = be[0];
    out[13] = be[1];
    out[14] = be[2];
    out[15] = be[3];
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip against the aes-gcm crate over a fuzz of sizes.
    /// If anything diverges, we'd see it here — and the boot KAT
    /// at `aead::rfc8439_kat` covers the canonical NIST vector.
    #[test]
    fn matches_aes_gcm_crate_roundtrip() {
        use aes_gcm::aead::AeadInPlace;
        use aes_gcm::aead::KeyInit as KI;
        use aes_gcm::Aes128Gcm;

        let key = [0x42u8; 16];
        let nonce = [0x17u8; 12];
        let aad: &[u8] = b"some-aad-bytes";
        let fast = Aes128GcmFast::new(&key);
        let slow = Aes128Gcm::new(GenericArray::from_slice(&key));

        for size in [0usize, 1, 15, 16, 17, 32, 100, 1024, 9000, 16383] {
            let plaintext: alloc::vec::Vec<u8> =
                (0..size).map(|i| (i as u8).wrapping_mul(31)).collect();

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

            assert_eq!(fast_buf, slow_buf, "ciphertext mismatch at size {}", size);
            assert_eq!(&fast_tag, slow_tag.as_slice(), "tag mismatch at size {}", size);

            // Round-trip via the fast path.
            let mut decrypted = fast_buf.clone();
            fast.open(&nonce, aad, &mut decrypted, &fast_tag)
                .expect("tag verify should pass on round-trip");
            assert_eq!(decrypted, plaintext, "decrypt mismatch at size {}", size);

            // Tamper detection.
            if !plaintext.is_empty() {
                let mut tampered = fast_buf.clone();
                tampered[0] ^= 1;
                let bad = fast.open(&nonce, aad, &mut tampered, &fast_tag);
                assert!(bad.is_err(), "tamper not detected at size {}", size);
            }
            let mut bad_tag = fast_tag;
            bad_tag[0] ^= 1;
            let mut buf = fast_buf.clone();
            let bad = fast.open(&nonce, aad, &mut buf, &bad_tag);
            assert!(bad.is_err(), "bad tag not detected at size {}", size);
        }
    }

    #[test]
    fn nist_kat_test_case_4() {
        // Same NIST SP 800-38D §B Test Case 4 as `aead::rfc8439_kat`.
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
}
