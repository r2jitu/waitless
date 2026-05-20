// net/tls_server_keys.rs — TLS 1.3 small key helpers used by the server.
//
// Shared primitives for the handshake handlers: the `finished` key
// derivation (HKDF-Expand-Label with a static `"finished"` label),
// HMAC-SHA256, and a constant-time comparison for 32-byte digests.
//
// Free functions — no shared state. Kept in their own module so they
// don't bloat tls_server.rs and so the set of places that touch raw
// traffic-secret bytes stays small and auditable.

use crate::schedule::{self as tls, HASH_LEN};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Derive a TLS 1.3 `finished_key` from a traffic secret via
/// HKDF-Expand-Label(label="finished", context=""). See RFC 8446
/// §4.4.4.
pub fn derive_finished_key(secret: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    tls::hkdf_expand_label(secret, b"finished", &[], &mut out);
    out
}

/// HMAC-SHA256 over `data` with `key`.
pub fn hmac_sha256(key: &[u8; HASH_LEN], data: &[u8]) -> [u8; HASH_LEN] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any slice");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut result = [0u8; HASH_LEN];
    result.copy_from_slice(&out);
    result
}

/// Constant-time equality for two 32-byte slices. `a` is a slice so
/// the caller can pass a byte slice from a parsed message; we check
/// the length up front.
///
/// Each byte is XORed and OR-accumulated, and the accumulator is fed
/// through `core::hint::black_box` so rustc can't short-circuit the
/// loop once `diff` is non-zero. That preserves the constant-time
/// property without pulling in the `subtle` crate.
pub fn ct_eq_32(a: &[u8], b: &[u8; HASH_LEN]) -> bool {
    if a.len() != HASH_LEN {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..HASH_LEN {
        diff = core::hint::black_box(diff | (a[i] ^ b[i]));
    }
    core::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_32_basics() {
        let a = [0x55u8; 32];
        let b = [0x55u8; 32];
        assert!(ct_eq_32(&a, &b));
        let mut c = b;
        c[0] ^= 1;
        assert!(!ct_eq_32(&a, &c));
        // Wrong length.
        assert!(!ct_eq_32(&[0u8; 16], &[0u8; 32]));
    }
}
