// net/tls_crypto.rs — Thin AEAD wrapper over the audited RustCrypto
// `chacha20poly1305` crate.
//
// Exposes a simple byte-slice `seal` / `open` API so `//net:tls` (and
// later `//net:quic`) don't have to deal with `generic-array`-typed
// `Nonce` / `Key` parameters directly. Matches the interface we want
// for any TLS 1.3 AEAD — `key: &[u8; 32]`, `nonce: &[u8; 12]`,
// `aad: &[u8]`, in-place `data`, 16-byte tag.
//
// Why a wrapper instead of using `chacha20poly1305` directly:
// - Keeps the `net/tls.rs` and `apps/test_tls` call sites identical
//   to what they were with the old hand-rolled impl.
// - Gives us one place to swap in `aes-gcm` later if a caller (QUIC)
//   negotiates `TLS_AES_128_GCM_SHA256`.
// - Removes the need for downstream crates to know about `generic-array`
//   / `aead` trait machinery.
//
// Constant-timeness + correctness are the responsibility of the
// upstream audited crate.

// (no-std + `extern crate` declarations live in lib.rs after the
// merger from //net:tls_crypto into //uni-tls.)

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};

// Lower-level primitives for the fused copy-and-encrypt path.
// `seal_chain_to` drives them by hand instead of
// going through the single-buffer `AeadInPlace` interface so the
// caller can read from immutable source parts and write to a
// separate destination in a single pass.
use chacha20::cipher::KeyIvInit;
use chacha20::ChaCha20;
use poly1305::universal_hash::{generic_array::GenericArray, UniversalHash};
use poly1305::Poly1305;

/// Size of the Poly1305 authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// Key length for ChaCha20-Poly1305 (and every other TLS 1.3 AEAD).
pub const KEY_LEN: usize = 32;

/// Nonce length for every TLS 1.3 AEAD.
pub const NONCE_LEN: usize = 12;

/// One-shot AEAD encrypt. `data` is the plaintext on input and the
/// ciphertext on output (same length — ChaCha20 is a stream cipher).
/// Returns the 16-byte Poly1305 authentication tag.
///
/// `aad` is additional authenticated data — authenticated but not
/// encrypted (e.g. TLS record header).
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
) -> [u8; TAG_LEN] {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, data)
        .expect("ChaCha20-Poly1305 encrypt: infallible for in-range buffers");
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(tag.as_slice());
    out
}


/// Fused copy-and-encrypt AEAD seal. Reads plaintext from each
/// part of `src_parts` (an iterator of `&[u8]`), XORs with the
/// ChaCha20 keystream while writing the ciphertext to consecutive
/// regions of `dst`, and accumulates one Poly1305 tag over the
/// resulting ciphertext. Returns the tag.
///
/// Differs from [`seal_chain`] in the source-vs-
/// destination shape: `seal_chain` operates in place on mutable
/// parts (caller has already coalesced plaintext into the parts
/// themselves), while `seal_chain_to` reads from immutable source
/// parts and writes ciphertext to a separate destination buffer.
/// The fused form lets the TLS record layer skip the copy-then-
/// encrypt-in-place pattern: instead of memcpy'ing chain bytes
/// into a scratch and then encrypting in place, encrypt-while-
/// copying in a single pass through the destination.
///
/// Uses `cipher::StreamCipher::apply_keystream_b2b` so the inner
/// XOR loop benefits from the chacha20 crate's SIMD backends.
///
/// `dst` must be at least as long as the sum of `src_parts`'
/// lengths. Bytes past the written prefix are left untouched.
pub fn seal_chain_to<'a, I>(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    src_parts: I,
    dst: &mut [u8],
) -> [u8; TAG_LEN]
where
    I: IntoIterator<Item = &'a [u8]>,
{
    use chacha20::cipher::StreamCipher;

    // Step 1: derive Poly1305 key from ChaCha20 counter 0 and skip
    // the rest of the first block (counter lands at 1 for plaintext).
    let mut cipher = ChaCha20::new(
        chacha20::Key::from_slice(key),
        chacha20::Nonce::from_slice(nonce),
    );
    let mut poly_key = [0u8; 32];
    cipher.apply_keystream(&mut poly_key);
    let mut discard = [0u8; 32];
    cipher.apply_keystream(&mut discard);

    let mut mac = Poly1305::new(GenericArray::from_slice(&poly_key));
    mac.update_padded(aad);

    // Step 2: walk src parts; for each one, encrypt-while-copying
    // from src_part into dst[cursor..cursor+len], then feed the
    // ciphertext bytes to Poly1305. Same 16-byte block straddle
    // logic as `seal_chain`.
    let mut cursor = 0usize;
    let mut block_buf = [0u8; 16];
    let mut block_pos = 0usize;

    for src_part in src_parts {
        let len = src_part.len();
        if len == 0 {
            continue;
        }
        let end = cursor + len;
        cipher
            .apply_keystream_b2b(src_part, &mut dst[cursor..end])
            .expect("src and dst slices have equal length");
        // Re-borrow as `&[u8]` for the Poly1305 read pass — the
        // mut borrow from `apply_keystream_b2b` ended on return.
        let mut data: &[u8] = &dst[cursor..end];
        cursor = end;

        // Drain any partial block carried over from a previous
        // part. `block_pos` is the number of bytes already in
        // `block_buf` from the previous iteration's tail.
        if block_pos > 0 {
            let take = (16 - block_pos).min(data.len());
            block_buf[block_pos..block_pos + take]
                .copy_from_slice(&data[..take]);
            block_pos += take;
            data = &data[take..];
            if block_pos == 16 {
                mac.update(&[*GenericArray::from_slice(&block_buf)]);
                block_buf = [0u8; 16];
                block_pos = 0;
            }
        }

        // Submit any whole 16-byte blocks then carry the tail.
        if !data.is_empty() {
            debug_assert_eq!(block_pos, 0);
            let full_bytes = data.len() & !15;
            if full_bytes > 0 {
                // SAFETY: contiguous `u8` bytes can be reinterpreted
                // as `&[GenericArray<u8, U16>]` (alignment 1, no
                // padding past element size).
                let blocks: &[GenericArray<u8, _>] = unsafe {
                    core::slice::from_raw_parts(
                        data.as_ptr() as *const GenericArray<u8, _>,
                        full_bytes / 16,
                    )
                };
                mac.update(blocks);
            }
            let tail = &data[full_bytes..];
            if !tail.is_empty() {
                block_buf[..tail.len()].copy_from_slice(tail);
                block_pos = tail.len();
            }
        }
    }

    // Final partial block (zero-padded). Skipped if total ended on
    // a 16-byte boundary.
    if block_pos > 0 {
        mac.update(&[*GenericArray::from_slice(&block_buf)]);
    }

    // Length block: aad_len_le8 || ct_len_le8.
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    len_block[8..].copy_from_slice(&(cursor as u64).to_le_bytes());
    mac.update(&[*GenericArray::from_slice(&len_block)]);

    let tag_arr = mac.finalize();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(tag_arr.as_slice());
    tag
}

/// One-shot AEAD decrypt + verify. Returns `Ok(())` on tag match and
/// decrypts `data` in place; returns `Err(())` on tag mismatch (in
/// which case `data` is left in an undefined state — the upstream
/// crate zeroises or leaves it, we don't rely on either).
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), ()> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(nonce), aad, data, Tag::from_slice(tag))
        .map_err(|_| ())
}

// ============================================================================
// Smoke tests — RFC 8439 §2.8.2 vector, verifies our wrapper matches
// the upstream crate's expected output exactly.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8439_aead_roundtrip() {
        let plaintext: &[u8] = &[
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e,
            0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20,
            0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
            0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e,
            0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72,
            0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
            0x74, 0x2e,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let expected_ct: [u8; 114] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];
        let expected_tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        let mut data = [0u8; 114];
        data.copy_from_slice(plaintext);
        let tag = seal(&key, &nonce, &aad, &mut data);
        assert_eq!(&data[..], &expected_ct[..]);
        assert_eq!(tag, expected_tag);

        let opened = open(&key, &nonce, &aad, &mut data, &tag);
        assert!(opened.is_ok());
        assert_eq!(&data[..], plaintext);
    }

    #[test]
    fn tamper_detection() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = [];
        let mut data = [0u8; 32];
        let mut tag = seal(&key, &nonce, &aad, &mut data);
        tag[0] ^= 0x01;
        let opened = open(&key, &nonce, &aad, &mut data, &tag);
        assert!(opened.is_err());
    }


    /// `seal_chain_to(key, nonce, aad, src_parts,
    /// dst)` must produce the same tag and the same ciphertext
    /// bytes as `seal(key, nonce, aad,
    /// concat(src_parts))` — i.e. the scatter-gather encrypt-while-
    /// copying form is byte-identical to a single-buffer in-place
    /// seal of the coalesced plaintext. Sweeps part layouts that
    /// exercise 16-byte block straddles, empty middle parts, and
    /// many-small-parts edge cases.
    #[test]
    fn seal_chain_to_matches_single_buffer() {
        let key = [0x77u8; 32];
        let nonce = [0x42u8; 12];
        let aad: &[u8] = b"chain-to-aad";
        let plaintext: alloc::vec::Vec<u8> = (0..256u32).map(|i| (i as u8).wrapping_mul(7)).collect();

        let layouts: &[&[usize]] = &[
            &[256],
            &[16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16],
            &[1, 255],
            &[15, 241],
            &[16, 240],
            &[17, 239],
            &[31, 225],
            &[32, 224],
            &[33, 223],
            &[7, 13, 23, 213],
            &[100, 0, 156],
            &[1; 256],
        ];

        for layout in layouts {
            let total: usize = layout.iter().sum();

            // Reference: single-buffer seal over the coalesced
            // plaintext. ChaCha20 is a stream cipher so the
            // ciphertext is independent of partitioning — the
            // scatter-gather seal_chain_to must produce the same
            // bytes.
            let mut ref_buf = plaintext[..total].to_vec();
            let ref_tag = seal(&key, &nonce, aad, &mut ref_buf);

            // seal_chain_to: read from immutable plaintext parts,
            // write ciphertext to a separate dst buffer.
            let src_bufs: alloc::vec::Vec<alloc::vec::Vec<u8>> = {
                let mut v = alloc::vec::Vec::new();
                let mut off = 0;
                for &len in layout.iter() {
                    v.push(plaintext[off..off + len].to_vec());
                    off += len;
                }
                v
            };
            let mut dst = alloc::vec![0u8; total];
            let to_tag = seal_chain_to(
                &key,
                &nonce,
                aad,
                src_bufs.iter().map(|v| v.as_slice()),
                &mut dst,
            );

            assert_eq!(
                ref_tag, to_tag,
                "tag mismatch for layout {:?}",
                layout
            );
            assert_eq!(
                dst, ref_buf,
                "ciphertext mismatch for layout {:?}",
                layout
            );
        }
    }
}
