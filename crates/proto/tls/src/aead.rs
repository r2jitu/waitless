// crates/proto/tls/aead.rs — Thin AEAD wrapper over the audited RustCrypto
// `aes-gcm` crate (TLS_AES_128_GCM_SHA256 — TLS 1.3's MTI cipher
// suite per RFC 8446 §9.1, and the universal preference of every
// modern client when AES-NI is available).
//
// Exposes a simple byte-slice `seal` / `open` API so `tls`,
// `quic`, and tests don't have to deal with `generic-array`-typed
// `Nonce` / `Key` parameters directly.
//
// Why AES-128-GCM (not ChaCha20-Poly1305):
//
//   - **Hardware acceleration is correct on every CPU we ship to.**
//     AES-NI + PCLMULQDQ have been on every Intel x86-64 since
//     Westmere (2010) and on Apple Silicon / ARMv8 FEAT_AES; the
//     `aes-gcm` crate's hardware path is verified-correct via its
//     own test vectors and via continued use in QUIC's Initial-
//     packet protection here.
//   - **The ChaCha20-Poly1305 SIMD backend in `chacha20` v0.9.1 is
//     broken on `x86_64-unknown-none`** — both SSE2 and AVX2
//     produce wrong keystream (verified by our boot-time KAT),
//     forcing us onto the software backend at ~700 MB/s. AES-NI
//     gives us ~3 GB/s with no such regression.
//   - **Browser cipher preference**: AES-128-GCM > ChaCha20-
//     Poly1305 on every TLS client where AES-NI is detected. So
//     the negotiated cipher in production was already going to be
//     AES-128-GCM if we'd offered it — we were just leaving
//     hardware acceleration on the floor by offering only ChaCha.
//
// Constant-timeness + correctness are the responsibility of the
// upstream audited crate (NCC Group audit on `aes-gcm`).

use aes_gcm::Aes128Gcm;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, KeyInit};

/// Size of the AES-GCM authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// Key length for AES-128-GCM (16 bytes — was 32 under
/// ChaCha20-Poly1305, the migration source).
pub const KEY_LEN: usize = 16;

/// Nonce length for every TLS 1.3 AEAD (also 12 for AES-GCM-12,
/// matching ChaCha20-Poly1305's nonce size — no change here).
pub const NONCE_LEN: usize = 12;

/// One-shot AEAD encrypt. `data` is the plaintext on input and the
/// ciphertext on output (same length — AES-CTR is a stream cipher
/// internally). Returns the 16-byte GHASH-derived authentication
/// tag.
///
/// `aad` is additional authenticated data — authenticated but not
/// encrypted (e.g. TLS record header).
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
) -> [u8; TAG_LEN] {
    let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, data)
        .expect("AES-128-GCM encrypt: infallible for in-range buffers");
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(tag.as_slice());
    out
}

/// Scatter-gather AEAD seal: read plaintext from each part of
/// `src_parts` (an iterator of `&[u8]`), copy into consecutive
/// regions of `dst`, then seal `dst[..total_len]` in place.
/// Returns the tag.
///
/// **Note vs the previous ChaCha20 fused implementation**: the
/// AES-GCM crate doesn't expose a fused copy-and-encrypt API, so
/// this version does a copy pass + an encrypt-in-place pass (vs
/// the old single fused pass). With AES-NI at ~3 GB/s the extra
/// memory traffic is rarely the bottleneck in practice — the
/// L1-resident chain bytes get re-read from cache, not DRAM. If a
/// future profile shows the copy is costing perf, dropping to
/// `aes::Aes128` + `ghash::GHash` lets us roll a true fused
/// AES-CTR + GHASH pass; we're avoiding that complexity until
/// data demands it.
///
/// `dst` must be at least as long as the sum of `src_parts`'
/// lengths. Bytes past the written prefix are left untouched.
pub fn seal_chain<'a, I>(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    src_parts: I,
    dst: &mut [u8],
) -> [u8; TAG_LEN]
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut cursor = 0usize;
    for src_part in src_parts {
        let n = src_part.len();
        if n == 0 {
            continue;
        }
        dst[cursor..cursor + n].copy_from_slice(src_part);
        cursor += n;
    }
    seal(key, nonce, aad, &mut dst[..cursor])
}

/// AEAD `open` failure. Tag-mismatch is the only AEAD failure
/// mode (the upstream `aes-gcm` crate's `Error` is itself a unit
/// type for the same reason). The TLS record layer maps it to
/// [`crate::record::RecordError::AeadOpenFailed`]; QUIC's
/// equivalent layer maps it to a packet-drop. A separate type
/// per crate (`tls::aead::AeadError`, `quic::crypto::AeadError`)
/// keeps the layering clean — TLS doesn't need a QUIC dep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadError;

/// One-shot AEAD decrypt + verify. Returns `Ok(())` on tag match
/// and decrypts `data` in place; returns `Err(AeadError)` on tag
/// mismatch (in which case `data` is left in an undefined state —
/// the upstream crate zeroises or leaves it, we don't rely on
/// either).
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), AeadError> {
    let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            aad,
            data,
            GenericArray::from_slice(tag),
        )
        .map_err(|_| AeadError)
}

// ============================================================================
// Boot-time known-answer test
// ============================================================================
//
// NIST SP 800-38D Appendix B Test Case 4 — AES-128-GCM with non-empty
// AAD. Lets the boot path verify the AES-NI / aes-gcm crate hot path
// is producing correct output before any TLS connection happens, and
// surfaces any future regression (Rust toolchain bump, crate version
// bump, alternate target) via the `/diag-panic` HTTP endpoint.

/// Result of [`rfc8439_kat`] (kept under the historical name even
/// after the AEAD migration — callers don't care about the test
/// vector source, just the pass/fail signal).
#[derive(Clone, Copy)]
pub struct KatFailure {
    pub first_diverge_at: usize,
    pub expected: u8,
    pub actual: u8,
    pub expected_window: [u8; 16],
    pub actual_window: [u8; 16],
}

/// Run NIST SP 800-38D §B (Test Case 4) known-answer test against
/// the live AES-128-GCM implementation. Returns `Ok(())` on
/// byte-for-byte match, or `Err(KatFailure)` carrying the first
/// divergence position + expected/actual byte windows for upstream-
/// bug reporting.
///
/// Designed for boot-time invocation: the caller logs the result
/// to the diag buffer so production deploys can detect a
/// compiler/CPU correctness regression in the AEAD path before any
/// TLS connection happens.
///
/// (Function name kept as `rfc8439_kat` for backwards compatibility
/// with the existing webserver init code; the test vector itself
/// is now the AES-GCM one.)
pub fn rfc8439_kat() -> Result<(), KatFailure> {
    // NIST SP 800-38D §B Test Case 4: 60-byte plaintext, 20-byte
    // AAD, 16-byte key, 12-byte IV.
    let key: [u8; 16] = [
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83,
        0x08,
    ];
    let nonce: [u8; 12] = [
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
    ];
    let aad: [u8; 20] = [
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
        0xef, 0xab, 0xad, 0xda, 0xd2,
    ];
    let plaintext: [u8; 60] = [
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26,
        0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31,
        0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49,
        0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
    ];
    let expected_ct: [u8; 60] = [
        0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4,
        0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac,
        0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac,
        0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91,
    ];

    let mut data = [0u8; 60];
    data.copy_from_slice(&plaintext);
    let _tag = seal(&key, &nonce, &aad, &mut data);
    for i in 0..60 {
        if data[i] != expected_ct[i] {
            let mut expected_window = [0u8; 16];
            let mut actual_window = [0u8; 16];
            let n = core::cmp::min(16, 60 - i);
            expected_window[..n].copy_from_slice(&expected_ct[i..i + n]);
            actual_window[..n].copy_from_slice(&data[i..i + n]);
            return Err(KatFailure {
                first_diverge_at: i,
                expected: expected_ct[i],
                actual: data[i],
                expected_window,
                actual_window,
            });
        }
    }
    Ok(())
}

// ============================================================================
// Boot-time KAT for the multi-chunk hand-rolled AES-128-GCM path
// ============================================================================
//
// `rfc8439_kat` above exercises the upstream `aes-gcm` crate (60-
// byte plaintext, single-chunk path). Our own `Aes128GcmFast` is
// what every TLS / QUIC record actually flows through — including
// the 8-block batched GHASH with deferred reduction. To get
// coverage of that hot path at boot (before any TLS connection),
// we cross-check our `seal` against upstream `Aes128Gcm::seal` on
// a 256-byte plaintext: two full 128-byte chunks, so the batched
// GHASH absorbs twice. Mismatch → KatFailure, captured to the
// diag buffer.
//
// The cross-check approach (vs an embedded golden vector) means
// any bit-order or reduction bug surfaces as `aead-fast-kat: FAIL
// at byte N`, with N pointing into the second chunk for batched-
// GHASH-only regressions — making the failure trivially
// attributable.

/// Cross-check `Aes128GcmFast` against the upstream
/// `Aes128Gcm` on a 256-byte plaintext (= 2 full 128-byte GHASH
/// chunks). Returns `Ok(())` on byte-for-byte match including
/// tag, `Err(KatFailure)` on the first divergence.
///
/// Boot-time companion to [`rfc8439_kat`]. The latter validates
/// the upstream crate compiled correctly; this one validates our
/// batched-GHASH hand-roll matches it. Both fire on every boot.
pub fn aes_gcm_fast_kat() -> Result<(), KatFailure> {
    use aes_gcm::Aes128Gcm;
    use aes_gcm::aead::AeadInPlace;
    use aes_gcm::aead::KeyInit as KI;
    use waitless_aes_gcm::Aes128GcmFast;

    // Arbitrary deterministic fixture. Key/nonce/AAD picked to
    // not collide with the rfc8439_kat above.
    let key: [u8; 16] = *b"GhashBatchKat0!!";
    let nonce: [u8; 12] = *b"ghash12bytes";
    let aad: [u8; 19] = *b"x86_64+aarch64-aes!";

    // 256 bytes = 2 full batched chunks; no tail. Pattern designed
    // to make every byte unique so a one-byte XOR error is visible.
    let mut plaintext = [0u8; 256];
    for (i, p) in plaintext.iter_mut().enumerate() {
        *p = (i as u8).wrapping_mul(37).wrapping_add(13);
    }

    // Reference: upstream aes-gcm.
    let slow = Aes128Gcm::new(GenericArray::from_slice(&key));
    let mut slow_buf = plaintext;
    let slow_tag = slow
        .encrypt_in_place_detached(GenericArray::from_slice(&nonce), &aad, &mut slow_buf)
        .expect("aes-gcm in-range");

    // Hand-roll.
    let fast = Aes128GcmFast::new(&key);
    let mut fast_buf = plaintext;
    let fast_tag = fast.seal(&nonce, &aad, &mut fast_buf);

    // Compare ciphertext byte by byte.
    for i in 0..256 {
        if fast_buf[i] != slow_buf[i] {
            let mut expected_window = [0u8; 16];
            let mut actual_window = [0u8; 16];
            let n = core::cmp::min(16, 256 - i);
            expected_window[..n].copy_from_slice(&slow_buf[i..i + n]);
            actual_window[..n].copy_from_slice(&fast_buf[i..i + n]);
            return Err(KatFailure {
                first_diverge_at: i,
                expected: slow_buf[i],
                actual: fast_buf[i],
                expected_window,
                actual_window,
            });
        }
    }
    // And the tag.
    for i in 0..16 {
        if fast_tag[i] != slow_tag.as_slice()[i] {
            let mut expected_window = [0u8; 16];
            let mut actual_window = [0u8; 16];
            expected_window.copy_from_slice(slow_tag.as_slice());
            actual_window.copy_from_slice(&fast_tag);
            return Err(KatFailure {
                // Encode "tag, byte i" as 256 + i so the diag
                // log distinguishes ciphertext divergence (<256)
                // from tag divergence (>=256).
                first_diverge_at: 256 + i,
                expected: slow_tag.as_slice()[i],
                actual: fast_tag[i],
                expected_window,
                actual_window,
            });
        }
    }
    Ok(())
}

// ============================================================================
// Smoke tests — NIST SP 800-38D Test Case 4 round-trip
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_aes128_gcm_roundtrip() {
        // Same vector as `rfc8439_kat` above, plus tag verification
        // and decrypt round-trip.
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

        let mut data = [0u8; 60];
        data.copy_from_slice(&plaintext);
        let tag = seal(&key, &nonce, &aad, &mut data);
        assert_eq!(&data[..], &expected_ct[..]);
        assert_eq!(tag, expected_tag);

        let opened = open(&key, &nonce, &aad, &mut data, &tag);
        assert!(opened.is_ok());
        assert_eq!(&data[..], &plaintext[..]);
    }

    #[test]
    fn tamper_detection() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let aad = [];
        let mut data = [0u8; 32];
        let mut tag = seal(&key, &nonce, &aad, &mut data);
        tag[0] ^= 0x01;
        let opened = open(&key, &nonce, &aad, &mut data, &tag);
        assert!(opened.is_err());
    }

    /// `seal_chain(key, nonce, aad, src_parts, dst)` must produce
    /// the same tag and ciphertext as `seal(key, nonce, aad,
    /// concat(src_parts))` — i.e. the scatter-gather form is
    /// byte-identical to a single-buffer in-place seal of the
    /// coalesced plaintext.
    #[test]
    fn seal_chain_matches_single_buffer() {
        let key = [0x77u8; 16];
        let nonce = [0x42u8; 12];
        let aad: &[u8] = b"chain-to-aad";
        let plaintext: alloc::vec::Vec<u8> =
            (0..256u32).map(|i| (i as u8).wrapping_mul(7)).collect();

        let layouts: &[&[usize]] = &[
            &[256],
            &[
                16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
            ],
            &[1, 255],
            &[15, 241],
            &[16, 240],
            &[17, 239],
            &[100, 0, 156],
            &[1; 256],
        ];

        for layout in layouts {
            let total: usize = layout.iter().sum();

            let mut ref_buf = plaintext[..total].to_vec();
            let ref_tag = seal(&key, &nonce, aad, &mut ref_buf);

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
            let to_tag = seal_chain(
                &key,
                &nonce,
                aad,
                src_bufs.iter().map(|v| v.as_slice()),
                &mut dst,
            );

            assert_eq!(ref_tag, to_tag, "tag mismatch for layout {:?}", layout);
            assert_eq!(dst, ref_buf, "ciphertext mismatch for layout {:?}", layout);
        }
    }

    #[test]
    fn boot_kat_passes() {
        assert!(rfc8439_kat().is_ok());
    }
}
