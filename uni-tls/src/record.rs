// net/tls_record.rs — TLS 1.3 record layer.
//
// Wraps plaintext in `TLSCiphertext` records (RFC 8446 §5) using an
// AEAD from `//net:tls_crypto`. Sans-io: the caller owns input/output
// byte buffers; this module is pure serialisation + cryptography.
//
// Wire format (§5.2):
//
// ```text
// struct {
//     ContentType opaque_type = application_data; /* 23 */
//     ProtocolVersion legacy_record_version = 0x0303;  /* TLS 1.2 */
//     uint16 length;  /* ciphertext + inner_type + padding + tag */
//     opaque encrypted_record[length];
// } TLSCiphertext;
// ```
//
// The plaintext that gets AEAD-sealed is `TLSInnerPlaintext`:
//
// ```text
// struct {
//     opaque content[TLSPlaintext.length];
//     ContentType type;            /* real content type; 22 = handshake, 23 = app_data */
//     uint8 zeros[length_of_padding];  /* we never pad */
// } TLSInnerPlaintext;
// ```
//
// The 5-byte TLSCiphertext header (opaque_type || legacy_record_version
// || length) serves as AAD for the AEAD, per §5.2.

// (no-std declaration lives in lib.rs after the merger. The former
// //net:tls crate is now this crate's sibling `schedule` module;
// //net:tls_crypto is now `aead`.)

use crate::aead as tls_crypto;
use crate::schedule as tls;

// ============================================================================
// Constants
// ============================================================================

/// TLS ContentType values (RFC 8446 §B.1).
pub mod content_type {
    pub const CHANGE_CIPHER_SPEC: u8 = 20;
    pub const ALERT: u8 = 21;
    pub const HANDSHAKE: u8 = 22;
    pub const APPLICATION_DATA: u8 = 23;
}

/// Size of the TLSCiphertext header: opaque_type(1) + version(2) + length(2).
pub const HEADER_LEN: usize = 5;

/// The opaque_type field is always `application_data` (23) for TLS 1.3
/// encrypted records — the real type is in the inner plaintext's trailer.
pub const OPAQUE_TYPE: u8 = content_type::APPLICATION_DATA;

/// The legacy_record_version field is always 0x0303 (TLS 1.2) for wire
/// compatibility with middleboxes that inspect this field.
pub const LEGACY_RECORD_VERSION: u16 = 0x0303;

/// AEAD tag length (16 bytes for AES-128-GCM).
pub const TAG_LEN: usize = tls_crypto::TAG_LEN;

/// Maximum TLSCiphertext record length, per RFC 8446 §5.2:
///     TLSInnerPlaintext <= 2^14 + 1 bytes
///     TLSCiphertext <= 2^14 + 1 + 255 bytes
/// We don't pad, so our cap is 2^14 + 1 + tag.
pub const MAX_RECORD_LEN: usize = 16385 + TAG_LEN;

/// Maximum inner plaintext length (content + one-byte type trailer) we
/// accept. 2^14 = 16384 of content, plus the one-byte type.
pub const MAX_INNER_PLAINTEXT: usize = 16385;

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// Output buffer too small for the encrypted record.
    OutputTooSmall,
    /// Input buffer didn't contain a full TLSCiphertext header.
    Truncated,
    /// Record length exceeds MAX_RECORD_LEN.
    RecordTooLarge,
    /// Received opaque_type wasn't `application_data` (23).
    UnexpectedOpaqueType,
    /// AEAD tag verification failed.
    AeadOpenFailed,
    /// Inner plaintext was empty or lacked a type trailer.
    BadInnerPlaintext,
    /// Plaintext input was longer than MAX_INNER_PLAINTEXT.
    InputTooLarge,
}

// ============================================================================
// Encrypt-throughput counters (TLS record layer)
// ============================================================================
//
// Bumped on every successful seal / open call with the plaintext
// byte count. Surfaced via `tls_encrypt_stats()` so /stats can
// report wire-bytes-per-second through the AEAD primitive (the
// guest-side cost of TLS, modulo header / framing memcpys which
// are already amortised by item A + B + D + the TLS-direct
// fast path).
//
// Counters are u64 atomics with Relaxed ops — each fetch_add is
// one extra cache-line touch per record. At 16 KiB / record that's
// negligible (~ns) next to the encrypt itself.
static TLS_ENCRYPT_BYTES: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
static TLS_ENCRYPT_RECORDS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
static TLS_DECRYPT_BYTES: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
static TLS_DECRYPT_RECORDS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

#[inline]
fn bump_encrypt(plaintext_len: usize) {
    use core::sync::atomic::Ordering::Relaxed;
    TLS_ENCRYPT_BYTES.fetch_add(plaintext_len as u64, Relaxed);
    TLS_ENCRYPT_RECORDS.fetch_add(1, Relaxed);
}

#[inline]
fn bump_decrypt(plaintext_len: usize) {
    use core::sync::atomic::Ordering::Relaxed;
    TLS_DECRYPT_BYTES.fetch_add(plaintext_len as u64, Relaxed);
    TLS_DECRYPT_RECORDS.fetch_add(1, Relaxed);
}

/// Snapshot of `(encrypt_bytes, encrypt_records, decrypt_bytes,
/// decrypt_records)` since boot. Differences across a sampling
/// window give per-second AEAD throughput.
pub fn encrypt_stats() -> (u64, u64, u64, u64) {
    use core::sync::atomic::Ordering::Relaxed;
    (
        TLS_ENCRYPT_BYTES.load(Relaxed),
        TLS_ENCRYPT_RECORDS.load(Relaxed),
        TLS_DECRYPT_BYTES.load(Relaxed),
        TLS_DECRYPT_RECORDS.load(Relaxed),
    )
}

// ============================================================================
// AAD helpers
// ============================================================================

/// Build the 5-byte AAD used by the AEAD for this record. `record_len`
/// is the value that will go into the length field — i.e. the total
/// encrypted bytes including the AEAD tag.
#[inline]
fn make_aad(record_len: u16) -> [u8; HEADER_LEN] {
    let mut aad = [0u8; HEADER_LEN];
    aad[0] = OPAQUE_TYPE;
    aad[1..3].copy_from_slice(&LEGACY_RECORD_VERSION.to_be_bytes());
    aad[3..5].copy_from_slice(&record_len.to_be_bytes());
    aad
}

// ============================================================================
// Seal: plaintext → TLSCiphertext
// ============================================================================

/// Encrypt `plaintext` with `traffic_key` and emit a full TLSCiphertext
/// record (5-byte header + ciphertext + tag) into `out`.
///
/// `inner_type` is the TLS content_type value that will be tucked into
/// the inner plaintext's trailer — typically `content_type::HANDSHAKE`
/// for handshake messages or `content_type::APPLICATION_DATA` for
/// application data.
///
/// Returns the number of bytes written to `out`.
///
/// Advances `traffic_key.seq` on success.
pub fn seal(
    traffic_key: &mut tls::TrafficKey,
    inner_type: u8,
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, RecordError> {
    if plaintext.len() >= MAX_INNER_PLAINTEXT {
        return Err(RecordError::InputTooLarge);
    }
    let inner_len = plaintext.len() + 1; // +1 for the type trailer
    let record_len = inner_len + TAG_LEN; // what goes in the header length field
    let total = HEADER_LEN + record_len;
    if out.len() < total {
        return Err(RecordError::OutputTooSmall);
    }
    if record_len > u16::MAX as usize {
        return Err(RecordError::RecordTooLarge);
    }

    // Write header.
    out[0] = OPAQUE_TYPE;
    out[1..3].copy_from_slice(&LEGACY_RECORD_VERSION.to_be_bytes());
    out[3..5].copy_from_slice(&(record_len as u16).to_be_bytes());

    // Write inner plaintext in place (content || type). No padding.
    let pt_start = HEADER_LEN;
    out[pt_start..pt_start + plaintext.len()].copy_from_slice(plaintext);
    out[pt_start + plaintext.len()] = inner_type;

    // AAD = header.
    let aad = make_aad(record_len as u16);

    // Seal in place: `traffic_key.seal` XOR-encrypts the buffer and
    // returns the tag.
    let pt_end = pt_start + inner_len;
    let tag = traffic_key.seal(&aad, &mut out[pt_start..pt_end]);

    // Append tag.
    out[pt_end..pt_end + TAG_LEN].copy_from_slice(&tag);
    bump_encrypt(plaintext.len());
    Ok(total)
}

// ============================================================================
// Open: TLSCiphertext → plaintext
// ============================================================================

/// Seal a TLSCiphertext record IN PLACE inside an [`uni_iobuf::IOBuf`]
/// that the caller has pre-sized with `headroom >= HEADER_LEN` and
/// `tailroom >= 1 + TAG_LEN`. The visible payload (`buf.data()`) is
/// the plaintext to encrypt; on success the IOBuf grows in both
/// directions:
///
///   before: `[5+ headroom][N plaintext bytes][17+ tailroom]`
///   after:  `[5 record header || N+1 ciphertext+type || 16 tag]`
///
/// Compared to `seal(plaintext, out)` this skips the plaintext memcpy
/// — the plaintext stays in the bytes the caller already wrote into
/// the IOBuf's payload region. Used by HTTPS body-send paths where
/// the app constructed body chunks via `IOBuf::new_with_reserved` so
/// every layer below TLS can prepend/append in place.
///
/// Errors:
///   * `OutputTooSmall` if headroom < HEADER_LEN or tailroom < 1 + TAG_LEN.
///   * `InputTooLarge` / `RecordTooLarge` for the same plaintext size
///     bounds as `seal`.
/// Advances `traffic_key.seq` on success.
/// Fused copy-and-encrypt sibling of [`seal_in_place`]. Reads
/// plaintext from `src_chain`, encrypts-while-copying into the
/// reserved space in `dst`, prepends the record header into
/// `dst`'s headroom and appends the type byte + AEAD tag into
/// `dst`'s tailroom.
///
/// Single pass through `dst`'s payload region — saves the
/// copy-then-encrypt-in-place double pass that the
/// `coalesce-into-scratch + seal_in_place` pattern would do.
///
/// Pre-conditions:
///   * `dst.headroom() >= HEADER_LEN` (5).
///   * `dst.tailroom() >= 1 + TAG_LEN` (17) AFTER fitting
///     `src_chain.total_len()` plaintext bytes.
///   * `dst`'s visible payload starts empty (`dst.len() == 0`).
///
/// On `Ok`, `dst.data()` is the wire-ready record:
/// `[5 record header || N ciphertext || encrypted type byte || 16 tag]`.
/// `traffic_key.seq` advances.
pub fn seal_chain_to(
    traffic_key: &mut tls::TrafficKey,
    inner_type: u8,
    src_chain: &uni_iobuf::IOBufChain,
    dst: &mut uni_iobuf::IOBuf,
) -> Result<(), RecordError> {
    let plaintext_len = src_chain.total_len();
    if plaintext_len >= MAX_INNER_PLAINTEXT {
        return Err(RecordError::InputTooLarge);
    }
    if dst.headroom() < HEADER_LEN {
        return Err(RecordError::OutputTooSmall);
    }
    let inner_len = plaintext_len + 1; // +1 for inner-content-type byte
    let record_len = inner_len + TAG_LEN;
    if record_len > u16::MAX as usize {
        return Err(RecordError::RecordTooLarge);
    }
    if dst.tailroom() < inner_len + TAG_LEN {
        return Err(RecordError::OutputTooSmall);
    }
    debug_assert_eq!(dst.len(), 0, "dst must start empty");

    // Step 1: extend dst's visible payload by `inner_len` bytes.
    // The new region (`dst.data_mut()[..inner_len]`) is where
    // ciphertext will land.
    let dst_slot = dst
        .extend_uninit(inner_len)
        .map_err(|_| RecordError::OutputTooSmall)?;

    // Step 2: fused encrypt-while-copying. Walk src_chain's parts
    // plus the trailing type byte, XOR keystream from each into
    // the corresponding region of `dst_slot`.
    let aad = make_aad(record_len as u16);
    let type_buf = [inner_type];
    let src_iter = src_chain
        .iter()
        .map(|p| p.data())
        .chain(core::iter::once(&type_buf[..]));
    let tag = traffic_key.seal_chain_to(&aad, src_iter, dst_slot);

    // Step 3: append the AEAD tag into the tailroom.
    dst.append_slice(&tag)
        .map_err(|_| RecordError::OutputTooSmall)?;

    // Step 4: prepend the TLSCiphertext record header.
    let mut hdr = [0u8; HEADER_LEN];
    hdr[0] = OPAQUE_TYPE;
    hdr[1..3].copy_from_slice(&LEGACY_RECORD_VERSION.to_be_bytes());
    hdr[3..5].copy_from_slice(&(record_len as u16).to_be_bytes());
    dst.prepend(&hdr).map_err(|_| RecordError::OutputTooSmall)?;

    bump_encrypt(plaintext_len);
    Ok(())
}

pub fn seal_in_place(
    traffic_key: &mut tls::TrafficKey,
    inner_type: u8,
    buf: &mut uni_iobuf::IOBuf,
) -> Result<(), RecordError> {
    let plaintext_len = buf.len();
    if plaintext_len >= MAX_INNER_PLAINTEXT {
        return Err(RecordError::InputTooLarge);
    }
    if buf.headroom() < HEADER_LEN {
        return Err(RecordError::OutputTooSmall);
    }
    if buf.tailroom() < 1 + TAG_LEN {
        return Err(RecordError::OutputTooSmall);
    }
    let inner_len = plaintext_len + 1; // +1 for the type trailer
    let record_len = inner_len + TAG_LEN;
    if record_len > u16::MAX as usize {
        return Err(RecordError::RecordTooLarge);
    }

    // Step 1: append the inner-content-type trailer (1 byte) into
    // the tailroom. The IOBuf's visible payload is now plaintext +
    // type byte, ready for AEAD-in-place.
    buf.append_slice(&[inner_type])
        .map_err(|_| RecordError::OutputTooSmall)?;

    // Step 2: AEAD seals over (plaintext || type) in place. AAD is
    // the (yet-to-be-prepended) record header.
    let aad = make_aad(record_len as u16);
    let pt_and_type = buf
        .data_mut()
        .ok_or(RecordError::OutputTooSmall)?;
    let tag = traffic_key.seal(&aad, pt_and_type);

    // Step 3: append the AEAD tag into the tailroom. After this
    // the IOBuf's visible payload is (ciphertext || type || tag).
    buf.append_slice(&tag)
        .map_err(|_| RecordError::OutputTooSmall)?;

    // Step 4: prepend the TLSCiphertext record header into the
    // headroom. Its `length` field covers (ciphertext || type ||
    // tag), exactly `record_len`.
    let mut hdr = [0u8; HEADER_LEN];
    hdr[0] = OPAQUE_TYPE;
    hdr[1..3].copy_from_slice(&LEGACY_RECORD_VERSION.to_be_bytes());
    hdr[3..5].copy_from_slice(&(record_len as u16).to_be_bytes());
    buf.prepend(&hdr).map_err(|_| RecordError::OutputTooSmall)?;

    bump_encrypt(plaintext_len);
    Ok(())
}

/// Decrypt the TLSCiphertext record at the start of `input` with
/// `traffic_key`. On success returns `(inner_type, plaintext_slice,
/// bytes_consumed)`.
///
/// `plaintext_slice` is a slice INTO `input` — the function decrypts in
/// place and returns a view of the decrypted content (minus the type
/// trailer).
///
/// Advances `traffic_key.seq` on success.
///
/// Returns `Err(Truncated)` if `input` doesn't contain a full header +
/// length bytes yet; caller should buffer more TCP bytes and retry.
pub fn open<'a>(
    traffic_key: &mut tls::TrafficKey,
    input: &'a mut [u8],
) -> Result<(u8, &'a [u8], usize), RecordError> {
    if input.len() < HEADER_LEN {
        return Err(RecordError::Truncated);
    }
    let opaque_type = input[0];
    // We accept both `application_data` (what an encrypted TLS 1.3
    // record should have) and also `change_cipher_spec` (because TLS 1.3
    // clients sometimes send a middlebox-compat CCS as a ContentType::
    // change_cipher_spec plaintext record — but that's handled by the
    // caller before calling open; here we insist on application_data).
    if opaque_type != OPAQUE_TYPE {
        return Err(RecordError::UnexpectedOpaqueType);
    }
    let record_len = u16::from_be_bytes([input[3], input[4]]) as usize;
    if record_len > MAX_RECORD_LEN || record_len < TAG_LEN + 1 {
        return Err(RecordError::RecordTooLarge);
    }
    let total = HEADER_LEN + record_len;
    if input.len() < total {
        return Err(RecordError::Truncated);
    }

    // Split ciphertext from tag.
    let tag_start = HEADER_LEN + record_len - TAG_LEN;
    let mut tag_arr = [0u8; TAG_LEN];
    tag_arr.copy_from_slice(&input[tag_start..HEADER_LEN + record_len]);

    let aad = make_aad(record_len as u16);
    let ct_range = HEADER_LEN..tag_start;

    traffic_key
        .open(&aad, &mut input[ct_range.clone()], &tag_arr)
        .map_err(|_| RecordError::AeadOpenFailed)?;

    // Decrypted. Strip zero-padding from the end to find the inner type.
    // RFC 8446 §5.2: remove trailing zero bytes (padding), the first
    // non-zero byte from the end is the type.
    let decrypted_len = ct_range.end - ct_range.start;
    let decrypted_start = ct_range.start;
    let decrypted_end = ct_range.end;
    let mut trailer_idx = decrypted_end;
    while trailer_idx > decrypted_start {
        trailer_idx -= 1;
        if input[trailer_idx] != 0 {
            break;
        }
    }
    if trailer_idx == decrypted_start && input[trailer_idx] == 0 {
        // All zeros — no type byte.
        return Err(RecordError::BadInnerPlaintext);
    }
    let inner_type = input[trailer_idx];
    let _ = decrypted_len; // consumed via decrypted_end

    bump_decrypt(trailer_idx - decrypted_start);
    Ok((
        inner_type,
        &input[decrypted_start..trailer_idx],
        total,
    ))
}

// ============================================================================
// Plaintext record helpers (for the handshake's pre-encryption records)
// ============================================================================

/// Build a plaintext TLSPlaintext record (used for ClientHello /
/// ServerHello — before encryption starts). The header is the real
/// content type + real legacy_record_version + length.
///
/// Returns the total bytes written = HEADER_LEN + body.len().
pub fn build_plaintext(
    real_content_type: u8,
    body: &[u8],
    out: &mut [u8],
) -> Result<usize, RecordError> {
    let total = HEADER_LEN + body.len();
    if out.len() < total {
        return Err(RecordError::OutputTooSmall);
    }
    if body.len() > u16::MAX as usize {
        return Err(RecordError::RecordTooLarge);
    }
    out[0] = real_content_type;
    out[1..3].copy_from_slice(&LEGACY_RECORD_VERSION.to_be_bytes());
    out[3..5].copy_from_slice(&(body.len() as u16).to_be_bytes());
    out[HEADER_LEN..total].copy_from_slice(body);
    Ok(total)
}

/// Parse a plaintext TLSPlaintext record. Returns
/// `(real_content_type, body_slice, bytes_consumed)`.
pub fn parse_plaintext(input: &[u8]) -> Result<(u8, &[u8], usize), RecordError> {
    if input.len() < HEADER_LEN {
        return Err(RecordError::Truncated);
    }
    let real_type = input[0];
    let len = u16::from_be_bytes([input[3], input[4]]) as usize;
    let total = HEADER_LEN + len;
    if len > MAX_RECORD_LEN {
        return Err(RecordError::RecordTooLarge);
    }
    if input.len() < total {
        return Err(RecordError::Truncated);
    }
    Ok((real_type, &input[HEADER_LEN..total], total))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_handshake() {
        let secret = [0x33u8; 32];
        let mut sender = tls::TrafficKey::from_secret(&secret);
        let mut receiver = tls::TrafficKey::from_secret(&secret);

        let plaintext = b"EncryptedExtensions body bytes";
        let mut out = [0u8; 256];

        let n = seal(
            &mut sender,
            content_type::HANDSHAKE,
            plaintext,
            &mut out,
        )
        .unwrap();
        // Header(5) + plaintext + type(1) + tag(16)
        assert_eq!(n, 5 + plaintext.len() + 1 + TAG_LEN);
        // Header bytes are correct.
        assert_eq!(out[0], OPAQUE_TYPE);
        assert_eq!(&out[1..3], &[0x03, 0x03]);
        assert_eq!(u16::from_be_bytes([out[3], out[4]]), (plaintext.len() + 1 + TAG_LEN) as u16);

        let (inner_type, pt, consumed) = open(&mut receiver, &mut out[..n]).unwrap();
        assert_eq!(inner_type, content_type::HANDSHAKE);
        assert_eq!(pt, plaintext);
        assert_eq!(consumed, n);

        // Sequence numbers advanced on both sides.
        assert_eq!(sender.seq, 1);
        assert_eq!(receiver.seq, 1);
    }

    #[test]
    fn seal_open_roundtrip_app_data() {
        let secret = [0xa5u8; 32];
        let mut sender = tls::TrafficKey::from_secret(&secret);
        let mut receiver = tls::TrafficKey::from_secret(&secret);

        let plaintext = b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let mut out = [0u8; 128];
        let n = seal(
            &mut sender,
            content_type::APPLICATION_DATA,
            plaintext,
            &mut out,
        )
        .unwrap();

        let (inner_type, pt, consumed) = open(&mut receiver, &mut out[..n]).unwrap();
        assert_eq!(inner_type, content_type::APPLICATION_DATA);
        assert_eq!(pt, plaintext);
        assert_eq!(consumed, n);
    }

    #[test]
    fn open_rejects_tampered_tag() {
        let secret = [0u8; 32];
        let mut sender = tls::TrafficKey::from_secret(&secret);
        let mut receiver = tls::TrafficKey::from_secret(&secret);

        let plaintext = b"x" ;
        let mut out = [0u8; 64];
        let n = seal(&mut sender, content_type::HANDSHAKE, plaintext, &mut out).unwrap();

        // Flip a tag bit.
        out[n - 1] ^= 1;
        let result = open(&mut receiver, &mut out[..n]);
        assert_eq!(result, Err(RecordError::AeadOpenFailed));
    }

    #[test]
    fn open_rejects_truncated_header() {
        let secret = [0u8; 32];
        let mut receiver = tls::TrafficKey::from_secret(&secret);
        let mut input = [0u8; 4];
        assert_eq!(open(&mut receiver, &mut input), Err(RecordError::Truncated));
    }

    #[test]
    fn open_rejects_wrong_opaque_type() {
        let secret = [0u8; 32];
        let mut receiver = tls::TrafficKey::from_secret(&secret);
        // ContentType::handshake (22) instead of 23
        let mut input = [22u8, 0x03, 0x03, 0x00, 0x11];
        // fill with junk; we never reach the AEAD step.
        assert_eq!(
            open(&mut receiver, &mut input),
            Err(RecordError::UnexpectedOpaqueType)
        );
    }

    #[test]
    fn plaintext_record_roundtrip() {
        let body = b"ServerHello bytes";
        let mut out = [0u8; 64];
        let n = build_plaintext(content_type::HANDSHAKE, body, &mut out).unwrap();
        assert_eq!(n, HEADER_LEN + body.len());
        assert_eq!(out[0], content_type::HANDSHAKE);
        assert_eq!(&out[1..3], &[0x03, 0x03]);
        assert_eq!(u16::from_be_bytes([out[3], out[4]]), body.len() as u16);

        let (ty, parsed, consumed) = parse_plaintext(&out[..n]).unwrap();
        assert_eq!(ty, content_type::HANDSHAKE);
        assert_eq!(parsed, body);
        assert_eq!(consumed, n);
    }

    /// `seal_chain_to` produces wire bytes that round-trip
    /// cleanly through `open`, including the multi-part AES-GCM
    /// 16-byte block-straddle path through GHASH.
    #[test]
    fn seal_chain_to_roundtrip() {
        let secret = [0xa5u8; 32];
        let mut sender = tls::TrafficKey::from_secret(&secret);
        let mut receiver = tls::TrafficKey::from_secret(&secret);

        // Multi-part src chain, chosen lengths to exercise the
        // 16-byte AES-GCM block-straddle path through GHASH.
        let mut src_chain = uni_iobuf::IOBufChain::new();
        for chunk in &[
            &b"HTTP/1.1 200 OK\r\n"[..],
            &b"Content-Length: 5\r\n\r\n"[..],
            &b"Hello"[..],
        ] {
            let mut buf = uni_iobuf::IOBuf::new_with_reserved(0, chunk.len(), 0);
            buf.append_slice(chunk).unwrap();
            src_chain.push_back(buf);
        }
        let plaintext_total: alloc::vec::Vec<u8> = src_chain
            .iter()
            .flat_map(|p| p.data().iter().copied())
            .collect();

        // dst sized for: 5 B header + plaintext + 1 B type + 16 B tag.
        let plaintext_len = plaintext_total.len();
        let mut dst = uni_iobuf::IOBuf::new_with_reserved(
            HEADER_LEN,
            plaintext_len + 1 + TAG_LEN,
            0,
        );

        seal_chain_to(
            &mut sender,
            content_type::APPLICATION_DATA,
            &src_chain,
            &mut dst,
        )
        .unwrap();

        // dst.data() is now the wire-ready record.
        let wire = dst.data();
        assert_eq!(wire.len(), HEADER_LEN + plaintext_len + 1 + TAG_LEN);

        // Round-trip via `open`.
        let mut wire_buf = wire.to_vec();
        let (inner_type, decrypted, consumed) =
            open(&mut receiver, &mut wire_buf).unwrap();
        assert_eq!(inner_type, content_type::APPLICATION_DATA);
        assert_eq!(decrypted, &plaintext_total[..]);
        assert_eq!(consumed, HEADER_LEN + plaintext_len + 1 + TAG_LEN);

        assert_eq!(sender.seq, 1);
        assert_eq!(receiver.seq, 1);
    }

    #[test]
    fn two_sequential_records_advance_seq() {
        let secret = [0x77u8; 32];
        let mut sender = tls::TrafficKey::from_secret(&secret);
        let mut receiver = tls::TrafficKey::from_secret(&secret);

        let pt1 = b"first";
        let pt2 = b"second";
        let mut buf = [0u8; 128];

        let n1 = seal(&mut sender, content_type::APPLICATION_DATA, pt1, &mut buf).unwrap();
        let (ty1, out1, _) = open(&mut receiver, &mut buf[..n1]).unwrap();
        assert_eq!(ty1, content_type::APPLICATION_DATA);
        assert_eq!(out1, pt1);

        let n2 = seal(&mut sender, content_type::APPLICATION_DATA, pt2, &mut buf).unwrap();
        let (ty2, out2, _) = open(&mut receiver, &mut buf[..n2]).unwrap();
        assert_eq!(ty2, content_type::APPLICATION_DATA);
        assert_eq!(out2, pt2);

        assert_eq!(sender.seq, 2);
        assert_eq!(receiver.seq, 2);
    }
}
