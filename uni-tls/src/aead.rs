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
pub fn chacha20poly1305_seal(
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

/// One-shot AEAD decrypt + verify. Returns `Ok(())` on tag match and
/// decrypts `data` in place; returns `Err(())` on tag mismatch (in
/// which case `data` is left in an undefined state — the upstream
/// crate zeroises or leaves it, we don't rely on either).
pub fn chacha20poly1305_open(
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
        let tag = chacha20poly1305_seal(&key, &nonce, &aad, &mut data);
        assert_eq!(&data[..], &expected_ct[..]);
        assert_eq!(tag, expected_tag);

        let opened = chacha20poly1305_open(&key, &nonce, &aad, &mut data, &tag);
        assert!(opened.is_ok());
        assert_eq!(&data[..], plaintext);
    }

    #[test]
    fn tamper_detection() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = [];
        let mut data = [0u8; 32];
        let mut tag = chacha20poly1305_seal(&key, &nonce, &aad, &mut data);
        tag[0] ^= 0x01;
        let opened = chacha20poly1305_open(&key, &nonce, &aad, &mut data, &tag);
        assert!(opened.is_err());
    }
}
