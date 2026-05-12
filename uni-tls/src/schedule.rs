// net/tls.rs — TLS 1.3 key schedule, transcript hash, and AEAD glue.
//
// Sans-io core of the TLS 1.3 handshake: everything you need to turn
// a PSK and/or (EC)DHE shared secret into the traffic keys that protect
// records. Used directly by a TLS-over-TCP server and, later, by the
// QUIC stack (QUIC uses the same TLS 1.3 handshake over its own
// CRYPTO frames, plus one more HKDF layer for packet protection).
//
// References:
//   RFC 8446 §7.1  TLS 1.3 key schedule
//   RFC 8446 §4.4  Key calculation (hash-input snapshots)
//   RFC 5869        HKDF
//   NIST SP 800-38D AES-GCM (the AEAD this schedule feeds)
//
// Design notes:
// - Hash: SHA-256 only (TLS_AES_128_GCM_SHA256, the suite we ship).
// - AEAD: AES-128-GCM only — RFC 8446 §9.1 mandatory-to-implement
//   suite, hardware-accelerated via AES-NI / FEAT_AES on every
//   target this project runs on.
// - KX: X25519 only (the TLS 1.3 default group, smallest code, and the
//   only MTI group shared with QUIC).
// - No allocator usage on the hot path: the schedule carries fixed
//   32-byte secrets and uses stack arrays.
// - No std, no cert parsing (yet), no SIGALG processing (yet). This
//   module stops at "we have traffic keys and can seal/open records".

// (no-std + `extern crate` declarations live in lib.rs after the
// merger from //net:tls into //uni-tls. `tls_crypto` was a separate
// crate; it's now this crate's sibling `aead` module.)

// Note: TrafficKey caches a pre-keyed `Aes128GcmFast` (our
// hand-rolled stitched AES-128-GCM — see `aes_gcm_fast.rs`),
// bypassing the upstream `aes-gcm` crate's open TODO that
// serialises AES-CTR and GHASH into two passes through memory.
// The `aead` shim still uses upstream `Aes128Gcm` for one-shot
// boot KAT / ticket envelope callers — those run rarely and the
// extra ~20× cost there is invisible next to the per-request hot
// path savings.
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// SHA-256 output length in bytes.
pub const HASH_LEN: usize = 32;

/// TLS 1.3 AEAD key length for `TLS_AES_128_GCM_SHA256`, our sole
/// negotiated cipher suite. 16 bytes — AES-128 key.
pub const KEY_LEN: usize = 16;

/// TLS 1.3 AEAD nonce length (all currently-defined suites use 12 bytes).
pub const IV_LEN: usize = 12;

/// Overwrite `buf` with zeroes in a way that the optimiser cannot elide.
///
/// Rust's compiler is free to skip a final write to a local that's about
/// to go out of scope; wrapping each byte in a `write_volatile` plus a
/// full compiler fence prevents that for the window where key material
/// still lives in an AEAD key / traffic secret. Not bullet-proof against
/// register / cache residue (we don't flush caches or scrub registers),
/// but it raises the bar meaningfully and matches the hygiene level of
/// the `zeroize` crate without pulling in another dep on the bare-metal
/// target.
pub fn secure_zero(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a mutable reference to one byte owned by this
        // slice; write_volatile with `0u8` is always valid.
        unsafe { core::ptr::write_volatile(b, 0); }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

// ============================================================================
// HKDF-Expand-Label (RFC 8446 §7.1)
// ============================================================================

/// Build the `HkdfLabel` structure that TLS 1.3 feeds into HKDF-Expand.
///
/// Wire format:
/// ```text
/// struct {
///     uint16 length;              // target output length
///     opaque label<7..255>;       // "tls13 " prepended to the base label
///     opaque context<0..255>;     // transcript-hash or empty
/// } HkdfLabel;
/// ```
///
/// We serialise into a fixed stack buffer: `2 + 1 + (6+label) + 1 + context`.
/// The longest label used by TLS 1.3 is "application traffic" at 19 bytes,
/// so `[u8; 64]` is plenty with room to spare.
fn build_hkdf_label(
    out_len: u16,
    label_suffix: &[u8],
    context: &[u8],
    buf: &mut [u8],
) -> usize {
    const PREFIX: &[u8] = b"tls13 ";
    let full_label_len = PREFIX.len() + label_suffix.len();
    let total = 2 + 1 + full_label_len + 1 + context.len();
    assert!(total <= buf.len(), "hkdf label buffer too small");

    buf[0..2].copy_from_slice(&out_len.to_be_bytes());
    buf[2] = full_label_len as u8;
    buf[3..3 + PREFIX.len()].copy_from_slice(PREFIX);
    buf[3 + PREFIX.len()..3 + full_label_len].copy_from_slice(label_suffix);
    buf[3 + full_label_len] = context.len() as u8;
    buf[4 + full_label_len..4 + full_label_len + context.len()].copy_from_slice(context);
    total
}

/// HKDF-Expand-Label with the given PRK, label, and context, writing
/// exactly `okm.len()` bytes of output.
///
/// `label_suffix` is the user-visible label without the "tls13 " prefix,
/// e.g. `b"c hs traffic"`, `b"key"`, `b"iv"`.
pub fn hkdf_expand_label(
    prk: &[u8; HASH_LEN],
    label_suffix: &[u8],
    context: &[u8],
    okm: &mut [u8],
) {
    let mut label_buf = [0u8; 64];
    let n = build_hkdf_label(okm.len() as u16, label_suffix, context, &mut label_buf);
    // Reconstruct the Hkdf from an existing PRK (salt was applied when
    // the PRK was computed).
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("PRK length = hash len");
    hk.expand(&label_buf[..n], okm)
        .expect("HKDF expand length is bounded");
}

/// Derive-Secret(Secret, Label, Messages) in RFC 8446 notation.
///
/// Equivalent to `HKDF-Expand-Label(secret, label, Transcript-Hash(messages), HashLen)`.
/// `transcript` is the hash of the handshake messages so far.
pub fn derive_secret(
    secret: &[u8; HASH_LEN],
    label_suffix: &[u8],
    transcript: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    hkdf_expand_label(secret, label_suffix, transcript, &mut out);
    out
}

/// HKDF-Extract: given an HMAC salt + input keying material, produce
/// a PRK (the "secret" used by Derive-Secret). Re-implements the core
/// RFC 5869 primitive directly so callers can pass salts other than
/// all-zeros (which `hkdf::Hkdf::new` supports but requires an Option).
fn hkdf_extract(salt: &[u8; HASH_LEN], ikm: &[u8]) -> [u8; HASH_LEN] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(salt).expect("HMAC accepts any slice");
    mac.update(ikm);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

// ============================================================================
// Transcript hash — running SHA-256 of concatenated handshake messages
// ============================================================================

/// Running SHA-256 transcript hash. Handshake messages are fed in
/// verbatim (in their on-the-wire form); `snapshot()` returns the
/// current digest without consuming the state.
pub struct Transcript {
    hasher: Sha256,
}

impl Transcript {
    pub fn new() -> Self {
        Transcript { hasher: Sha256::new() }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Snapshot the current hash without consuming it — needed for the
    /// "transcript-hash so far" inputs to Derive-Secret at each stage.
    pub fn snapshot(&self) -> [u8; HASH_LEN] {
        let mut clone = self.hasher.clone();
        // Finalise the clone; the original continues to accumulate.
        let digest = clone.finalize_reset();
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(&digest);
        out
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

/// Empty-transcript hash — SHA-256("") — used at the start of the
/// "derived" Derive-Secret calls when there are no handshake messages
/// yet.
pub fn empty_transcript_hash() -> [u8; HASH_LEN] {
    let mut h = Sha256::new();
    h.update([]);
    let digest = h.finalize();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

// ============================================================================
// Traffic key pair: (AEAD key, IV)
// ============================================================================

/// Per-direction traffic keys: a pre-keyed AES-128-GCM cipher plus
/// the static nonce base. RFC 8446 §5.3 specifies the per-record
/// nonce as `iv XOR seq_be`.
///
/// Storing the keyed `Aes128Gcm` directly (vs the previous raw
/// `[u8; KEY_LEN]`) means each `seal`/`open` skips the AES-128 key
/// schedule + GHASH H-table init that `Aes128Gcm::new` does — that
/// work happens once per TrafficKey, not once per record. With
/// AES-NI it's only ~200 cycles, but at >100 K records/s the
/// per-conn caching surfaces above noise on TLS-record-heavy
/// workloads.
///
/// `aes-gcm`'s `zeroize` feature (enabled in our Cargo.toml)
/// installs a `Drop` impl on `Aes128Gcm` that zeroes the round
/// keys, replacing the per-byte `secure_zero` we used to do on the
/// raw key.
#[derive(Clone)]
pub struct TrafficKey {
    cipher: crate::aes_gcm_fast::Aes128GcmFast,
    pub iv: [u8; IV_LEN],
    pub seq: u64,
}

impl Drop for TrafficKey {
    fn drop(&mut self) {
        // The `aes::Aes128` round-keys + `polyval::Polyval` GHASH
        // state inside `Aes128GcmFast` aren't currently
        // explicitly zeroed (neither crate has `zeroize`
        // enabled in our build). The previous design used
        // `aes-gcm`'s `zeroize` feature for this. Trade-off:
        // saved a dep + got the stitched perf, lost defense in
        // depth against same-process memory disclosure. We
        // accept that on bare-metal where there's no other
        // process to disclose to; revisit if we ever run on a
        // multi-tenant target.
        // The IV is non-secret per RFC 8446 §5.3 (xored with
        // `seq` to form the per-record nonce, sent in the clear
        // as associated data anyway), but zero it for hygiene
        // with the same scrubbing primitive used for stack
        // secrets.
        secure_zero(&mut self.iv);
    }
}

impl TrafficKey {
    /// Derive `(key, iv)` from a 32-byte traffic secret via
    /// `HKDF-Expand-Label(secret, "key"/"iv", "", …)`, then
    /// instantiate the `Aes128Gcm` cipher and discard the raw key.
    pub fn from_secret(secret: &[u8; HASH_LEN]) -> Self {
        let mut key = [0u8; KEY_LEN];
        let mut iv = [0u8; IV_LEN];
        hkdf_expand_label(secret, b"key", &[], &mut key);
        hkdf_expand_label(secret, b"iv", &[], &mut iv);
        let cipher = crate::aes_gcm_fast::Aes128GcmFast::new(&key);
        // Wipe the raw key now that it's been folded into the
        // cipher's round-key state — no plaintext key bytes
        // outlive this call.
        secure_zero(&mut key);
        TrafficKey { cipher, iv, seq: 0 }
    }

    /// XOR the sequence number into the static IV to form the per-record
    /// nonce (RFC 8446 §5.3).
    pub fn nonce_for_seq(&self, seq: u64) -> [u8; IV_LEN] {
        let mut nonce = self.iv;
        let seq_be = seq.to_be_bytes();
        // iv is 12 bytes, seq occupies the low 8.
        for i in 0..8 {
            nonce[4 + i] ^= seq_be[i];
        }
        nonce
    }

    /// Seal `data` in place with the next sequence number, returning
    /// the 16-byte tag. Auto-increments `seq`.
    pub fn seal(&mut self, aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        let nonce = self.nonce_for_seq(self.seq);
        self.seq = self.seq.wrapping_add(1);
        self.cipher.seal(&nonce, aad, data)
    }

    /// Fused copy-and-encrypt N-way variant of [`Self::seal`].
    /// Reads plaintext from `src_parts` (immutable byte slices),
    /// writes ciphertext to consecutive regions of `dst`,
    /// computes one AES-GCM authentication tag, and returns it.
    /// Auto-increments `seq`.
    ///
    /// Lets the TLS record layer skip the copy-then-encrypt-in-
    /// place pattern: instead of memcpy'ing chain bytes into a
    /// scratch and then encrypting in place, encrypt-while-
    /// copying in a single pass through `dst`. `dst` must be at
    /// least as long as the sum of `src_parts`' lengths.
    pub fn seal_chain_to<'a, I>(
        &mut self,
        aad: &[u8],
        src_parts: I,
        dst: &mut [u8],
    ) -> [u8; 16]
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let nonce = self.nonce_for_seq(self.seq);
        self.seq = self.seq.wrapping_add(1);
        self.cipher.seal_chain_to(&nonce, aad, src_parts, dst)
    }

    /// Open `data` in place; returns Err on tag mismatch. Auto-increments
    /// `seq` on success.
    pub fn open(&mut self, aad: &[u8], data: &mut [u8], tag: &[u8; 16]) -> Result<(), ()> {
        let nonce = self.nonce_for_seq(self.seq);
        self.cipher.open(&nonce, aad, data, tag)?;
        self.seq = self.seq.wrapping_add(1);
        Ok(())
    }
}


// ============================================================================
// TLS 1.3 key schedule
// ============================================================================

/// Full TLS 1.3 key schedule state. Walks the cascade of Early /
/// Handshake / Master secrets and exposes the derived traffic secrets
/// at each stage. A caller running a TLS handshake (or QUIC handshake)
/// feeds in the PSK (optional), the (EC)DHE shared secret, and the
/// transcript hash at each transition.
pub struct KeySchedule {
    /// Current "secret" in the RFC 8446 §7.1 diagram — either the Early,
    /// Handshake, or Master secret depending on progress.
    secret: [u8; HASH_LEN],
}

impl Drop for KeySchedule {
    fn drop(&mut self) {
        secure_zero(&mut self.secret);
    }
}

/// The two traffic-secret outputs from the handshake stage.
#[derive(Clone)]
pub struct HandshakeSecrets {
    pub client_hs: [u8; HASH_LEN],
    pub server_hs: [u8; HASH_LEN],
}

impl Drop for HandshakeSecrets {
    fn drop(&mut self) {
        secure_zero(&mut self.client_hs);
        secure_zero(&mut self.server_hs);
    }
}

/// The two traffic-secret outputs from the application stage, plus the
/// exporter and resumption secrets (parked for later use).
#[derive(Clone)]
pub struct ApplicationSecrets {
    pub client_ap: [u8; HASH_LEN],
    pub server_ap: [u8; HASH_LEN],
    pub exporter: [u8; HASH_LEN],
}

impl Drop for ApplicationSecrets {
    fn drop(&mut self) {
        secure_zero(&mut self.client_ap);
        secure_zero(&mut self.server_ap);
        secure_zero(&mut self.exporter);
    }
}

impl KeySchedule {
    /// Start the schedule in the "early" stage without a PSK.
    /// Equivalent to `HKDF-Extract(0, 0)`.
    pub fn new_without_psk() -> Self {
        let zeros = [0u8; HASH_LEN];
        KeySchedule {
            secret: hkdf_extract(&zeros, &zeros),
        }
    }

    /// Start the schedule with a pre-shared key.
    pub fn new_with_psk(psk: &[u8]) -> Self {
        let zeros = [0u8; HASH_LEN];
        KeySchedule {
            secret: hkdf_extract(&zeros, psk),
        }
    }

    /// Early secret as a slice (mainly for tests).
    pub fn secret(&self) -> &[u8; HASH_LEN] {
        &self.secret
    }

    /// Derive the client early-data traffic secret (RFC 8446 §7.1):
    ///
    ///     client_early_traffic = Derive-Secret(early_secret,
    ///                                          "c e traffic",
    ///                                          ClientHello)
    ///
    /// Returned independently from a state transition because in
    /// QUIC 0-RTT the server needs early-data keys *immediately*
    /// after parsing CH (so it can decrypt 0-RTT packets that
    /// arrive in the same datagram), without yet committing to
    /// the handshake-stage state. `transcript` is the hash of
    /// just the ClientHello (`Transcript-Hash(ClientHello)`).
    /// Returns the 32-byte traffic secret; caller derives AEAD
    /// keys via `derive_chacha_keys` (or equivalent).
    ///
    /// Only meaningful on a `KeySchedule::new_with_psk(...)` —
    /// `new_without_psk` produces an early_secret tied to the
    /// zero-PSK and the resulting traffic secret can't decrypt
    /// any client traffic.
    pub fn early_traffic(&self, transcript: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
        derive_secret(&self.secret, b"c e traffic", transcript)
    }

    /// Transition from the Early stage to the Handshake stage by
    /// extracting the handshake secret from the (EC)DHE shared secret.
    /// `transcript` is the hash of all handshake messages so far
    /// (ClientHello .. ServerHello).
    pub fn enter_handshake(
        &mut self,
        dhe_shared: &[u8],
        transcript: &[u8; HASH_LEN],
    ) -> HandshakeSecrets {
        // 1. derived = Derive-Secret(early_secret, "derived", "")
        let derived = derive_secret(&self.secret, b"derived", &empty_transcript_hash());
        // 2. handshake_secret = HKDF-Extract(derived, DHE)
        let handshake_secret = hkdf_extract(&derived, dhe_shared);
        self.secret = handshake_secret;
        // 3. client_hs_traffic = Derive-Secret(handshake_secret, "c hs traffic", transcript)
        let client_hs = derive_secret(&self.secret, b"c hs traffic", transcript);
        let server_hs = derive_secret(&self.secret, b"s hs traffic", transcript);
        HandshakeSecrets { client_hs, server_hs }
    }

    /// Compute the TLS 1.3 resumption_master_secret without
    /// consuming `self.secret`. RFC 8446 §7.1:
    ///
    ///     resumption_master_secret =
    ///         Derive-Secret(master_secret, "res master",
    ///                       Transcript-Hash(ClientHello..ClientFinished))
    ///
    /// Caller must invoke this AFTER `enter_application` (which is what
    /// transitions `self.secret` from handshake_secret → master_secret)
    /// AND AFTER updating the transcript with the client Finished.
    /// Returns the 32-byte resumption secret; the caller seals it
    /// inside a ticket and forgets it.
    pub fn resumption_secret(&self, transcript: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
        derive_secret(&self.secret, b"res master", transcript)
    }

    /// Transition from the Handshake stage to the Application stage.
    /// `transcript` is the hash through ServerFinished.
    pub fn enter_application(
        &mut self,
        transcript: &[u8; HASH_LEN],
    ) -> ApplicationSecrets {
        // 1. derived = Derive-Secret(handshake_secret, "derived", "")
        let derived = derive_secret(&self.secret, b"derived", &empty_transcript_hash());
        // 2. master_secret = HKDF-Extract(derived, 0)
        let zeros = [0u8; HASH_LEN];
        let master_secret = hkdf_extract(&derived, &zeros);
        self.secret = master_secret;
        // 3. derive the three application-stage secrets.
        let client_ap = derive_secret(&self.secret, b"c ap traffic", transcript);
        let server_ap = derive_secret(&self.secret, b"s ap traffic", transcript);
        let exporter = derive_secret(&self.secret, b"exp master", transcript);
        ApplicationSecrets {
            client_ap,
            server_ap,
            exporter,
        }
    }
}

// ============================================================================
// X25519 key exchange wrappers
// ============================================================================

/// A fresh X25519 server-side ephemeral keypair. The caller extracts
/// `public_bytes()` for the ServerHello key_share and consumes the
/// whole struct via `shared_secret()` when the client's share arrives.
pub struct X25519ServerKey {
    secret: x25519_dalek::StaticSecret,
    public: x25519_dalek::PublicKey,
}

impl X25519ServerKey {
    /// Generate a fresh keypair from 32 bytes of entropy.
    /// Callers pass kernel-sourced randomness (jitter + cycle counter
    /// + PRNG); see `uni_kernel::rng` once it exists.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let secret = x25519_dalek::StaticSecret::from(seed);
        let public = x25519_dalek::PublicKey::from(&secret);
        X25519ServerKey { secret, public }
    }

    /// 32-byte public key to put in a ServerHello KeyShareEntry.
    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// Compute the shared secret with the client's public key.
    /// Consumes `self` so the secret can never be reused.
    pub fn shared_secret(self, client_public: &[u8; 32]) -> [u8; 32] {
        let client_pk = x25519_dalek::PublicKey::from(*client_public);
        let shared = self.secret.diffie_hellman(&client_pk);
        *shared.as_bytes()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The "tls13 " prefix + label serialisation must match the wire
    /// format in RFC 8446 §7.1 exactly. We don't have a canonical
    /// RFC 8446 test vector for `build_hkdf_label` alone, so we check
    /// the serialisation by hand.
    #[test]
    fn hkdf_label_format_matches_spec() {
        let mut buf = [0u8; 64];
        let n = build_hkdf_label(32, b"key", &[], &mut buf);
        // Expected:
        //   [0x00, 0x20]             length = 32
        //   [0x09]                   full label length = 6 + 3
        //   "tls13 key"              full label
        //   [0x00]                   context length = 0
        let expected: &[u8] = &[
            0x00, 0x20, 0x09, b't', b'l', b's', b'1', b'3', b' ', b'k', b'e', b'y', 0x00,
        ];
        assert_eq!(&buf[..n], expected);
    }

    /// HKDF-Expand-Label is deterministic and its output length equals
    /// the caller-requested length. This is a self-consistency test;
    /// it's not a known-answer vector but it catches most wire-format
    /// mistakes (length mismatch, label prefix typo).
    #[test]
    fn hkdf_expand_label_is_deterministic() {
        let prk = [0x42u8; HASH_LEN];
        let mut out1 = [0u8; 16];
        let mut out2 = [0u8; 16];
        hkdf_expand_label(&prk, b"key", &[], &mut out1);
        hkdf_expand_label(&prk, b"key", &[], &mut out2);
        assert_eq!(out1, out2);

        // Different label → different output.
        let mut out3 = [0u8; 16];
        hkdf_expand_label(&prk, b"iv", &[], &mut out3);
        assert_ne!(out1, out3);
    }

    /// Verify the key-schedule cascade: two independent runs with the
    /// same inputs must produce the same traffic secrets, but a single
    /// bit flip in the DHE secret must scramble them completely.
    #[test]
    fn key_schedule_cascade_deterministic() {
        let dhe = [0x77u8; 32];
        let transcript = [0x11u8; HASH_LEN];

        let mut sched_a = KeySchedule::new_without_psk();
        let hs_a = sched_a.enter_handshake(&dhe, &transcript);

        let mut sched_b = KeySchedule::new_without_psk();
        let hs_b = sched_b.enter_handshake(&dhe, &transcript);

        assert_eq!(hs_a.client_hs, hs_b.client_hs);
        assert_eq!(hs_a.server_hs, hs_b.server_hs);
        // Client and server secrets must differ (different labels).
        assert_ne!(hs_a.client_hs, hs_a.server_hs);

        // Flip one bit of the DHE input.
        let mut dhe_flipped = dhe;
        dhe_flipped[0] ^= 1;
        let mut sched_c = KeySchedule::new_without_psk();
        let hs_c = sched_c.enter_handshake(&dhe_flipped, &transcript);
        assert_ne!(hs_a.client_hs, hs_c.client_hs);
    }

    /// `resumption_secret` derives a fresh 32-byte secret from the
    /// post-application master_secret + transcript-through-Finished.
    /// Calling it twice with the same transcript yields the same
    /// output; different transcripts yield different outputs and
    /// neither matches `client_ap` / `server_ap` / `exporter`.
    #[test]
    fn resumption_secret_is_deterministic_and_distinct() {
        let dhe = [0x66u8; 32];
        let mid_transcript = [0x44u8; HASH_LEN];
        let final_transcript = [0x55u8; HASH_LEN];
        let post_cf_transcript = [0x99u8; HASH_LEN];

        let mut sched = KeySchedule::new_without_psk();
        let _hs = sched.enter_handshake(&dhe, &mid_transcript);
        let app = sched.enter_application(&final_transcript);

        let rms_a = sched.resumption_secret(&post_cf_transcript);
        let rms_b = sched.resumption_secret(&post_cf_transcript);
        assert_eq!(rms_a, rms_b);
        // Different transcript → different secret.
        let rms_c = sched.resumption_secret(&final_transcript);
        assert_ne!(rms_a, rms_c);
        // Distinct from every application-stage secret.
        assert_ne!(rms_a, app.client_ap);
        assert_ne!(rms_a, app.server_ap);
        assert_ne!(rms_a, app.exporter);
    }

    /// Application-stage secrets differ from handshake-stage secrets
    /// (same transcript but different HKDF labels / different PRK).
    #[test]
    fn application_stage_derives_different_secrets() {
        let dhe = [0x33u8; 32];
        let mid_transcript = [0x44u8; HASH_LEN];
        let final_transcript = [0x55u8; HASH_LEN];

        let mut sched = KeySchedule::new_without_psk();
        let hs = sched.enter_handshake(&dhe, &mid_transcript);
        let app = sched.enter_application(&final_transcript);

        assert_ne!(hs.client_hs, app.client_ap);
        assert_ne!(hs.server_hs, app.server_ap);
        assert_ne!(app.client_ap, app.exporter);
    }

    /// Traffic keys derived from a secret are 32+12 bytes and applying
    /// them seal→open round-trips plaintext correctly with the per-seq
    /// nonce.
    #[test]
    fn traffic_key_seal_open_roundtrip() {
        let secret = [0xaau8; HASH_LEN];
        let mut tk_send = TrafficKey::from_secret(&secret);
        let mut tk_recv = TrafficKey::from_secret(&secret);

        let aad = b"record_header";
        let plaintext = b"Hello, TLS 1.3 record payload!";
        let mut buf = [0u8; 64];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        let tag = tk_send.seal(aad, &mut buf[..plaintext.len()]);
        // Ciphertext should differ from plaintext (with overwhelming prob).
        assert_ne!(&buf[..plaintext.len()], plaintext);

        tk_recv
            .open(aad, &mut buf[..plaintext.len()], &tag)
            .expect("tag must verify on roundtrip");
        assert_eq!(&buf[..plaintext.len()], plaintext);

        // Sequence numbers advanced on both sides.
        assert_eq!(tk_send.seq, 1);
        assert_eq!(tk_recv.seq, 1);
    }

    /// X25519 round-trip: two parties with different keypairs derive
    /// the same shared secret.
    #[test]
    fn x25519_shared_secret_roundtrip() {
        let alice = X25519ServerKey::from_seed([0x10; 32]);
        let bob = X25519ServerKey::from_seed([0x20; 32]);
        let alice_pub = alice.public_bytes();
        let bob_pub = bob.public_bytes();
        let ss_ab = alice.shared_secret(&bob_pub);
        let ss_ba = bob.shared_secret(&alice_pub);
        assert_eq!(ss_ab, ss_ba);
    }

    /// Transcript hash snapshots are stable across resume points.
    #[test]
    fn transcript_snapshot_is_stable() {
        let mut t = Transcript::new();
        t.update(b"ClientHello");
        let s1 = t.snapshot();
        // Re-snapshot without adding more data returns the same value.
        let s1b = t.snapshot();
        assert_eq!(s1, s1b);
        // Adding more data changes the snapshot.
        t.update(b"ServerHello");
        let s2 = t.snapshot();
        assert_ne!(s1, s2);
    }
}
