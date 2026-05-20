// uni-quic/src/conn/keys.rs — per-direction packet protection
// cipher cache + the `Connection` hooks that derive / rotate
// those keys.
//
// `DirKeys` caches the keyed AES-128-GCM (AEAD) and AES-128 (HP)
// ciphers so each packet seal / open / hp_mask skips the AES
// round-key expansion + GHASH H-table init that
// `Aes128Gcm::new` / `Aes128::new` did per call previously.
//
// `advance_tls` drives the TLS state machine forward and, as
// fresh stage secrets become available, derives the
// corresponding `DirKeys` pair (Handshake, then Application);
// `rotate_recv_keys` implements RFC 9001 §6 key updates on the
// receive side.

use alloc::vec::Vec;

use super::{ConnError, ConnState, Connection};
use crate::crypto::{
    AES_KEY_LEN, HP_MASK_LEN, HP_SAMPLE_LEN, NONCE_LEN, TAG_LEN, derive_aes128_keys,
    next_traffic_secret,
};
use crate::tls::QuicTlsState;
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{AeadInPlace, KeyInit, generic_array::GenericArray};
use aes_gcm::aes::Aes128;
use aes_gcm::aes::cipher::BlockEncrypt;
use tls::TlsServerConfig;

// ============================================================================
// Per-direction packet protection keys
// ============================================================================

/// AEAD/HP cipher state for one direction (client→server or
/// server←client) at one packet-protection stage (Initial,
/// Handshake, or 1-RTT). Always AES-128-GCM (16-byte AEAD key,
/// 12-byte IV, 16-byte HP key) since `TLS_AES_128_GCM_SHA256` is
/// our sole negotiated cipher suite.
///
/// Caches the keyed `Aes128Gcm` (AEAD) and `Aes128` (ECB-mode HP
/// cipher) so each packet-protection / unprotection skips the AES
/// round-key expansion + GHASH H-table init that `Aes128Gcm::new`
/// and `Aes128::new` did per call previously. The work happens once
/// per `from_*` call (once per stage, plus once per RFC 9001 §6.1
/// key-phase rotation on the AEAD half) instead of once per packet.
///
/// On QUIC large-body workloads (e.g. `h3_diagnostics_max`'s ~9 KiB
/// body fragmented into ~7 datagrams per request) this matters
/// because the previous per-packet new-then-drop pattern paid the
/// AES key schedule + (with the `zeroize` feature on aes-gcm) a
/// zeroize-on-Drop on every seal/open.
///
/// Pre-migration this struct held only raw key bytes
/// (`[u8; AES_KEY_LEN]` × 2) plus an `is_chacha` discriminant for
/// the now-removed ChaCha20-Poly1305 path; the AES-128-GCM
/// migration dropped the discriminant, and this commit drops the
/// raw key bytes in favour of the keyed ciphers.
#[derive(Clone)]
pub(crate) struct DirKeys {
    pub(super) aead_cipher: Aes128Gcm,
    pub(super) iv: [u8; NONCE_LEN],
    pub(super) hp_cipher: Aes128,
}

impl DirKeys {
    /// Build a fresh `DirKeys` from raw key bytes — the AES
    /// `Aes128Gcm` and `Aes128` ciphers are constructed once here
    /// and then reused for every subsequent seal / open / hp_mask.
    pub(super) fn new(
        aead_key: &[u8; AES_KEY_LEN],
        iv: &[u8; NONCE_LEN],
        hp_key: &[u8; AES_KEY_LEN],
    ) -> Self {
        DirKeys {
            aead_cipher: Aes128Gcm::new(GenericArray::from_slice(aead_key)),
            iv: *iv,
            hp_cipher: Aes128::new(GenericArray::from_slice(hp_key)),
        }
    }

    pub(super) fn from_initial(k: &crate::crypto::InitialKeys) -> Self {
        Self::new(&k.key, &k.iv, &k.hp)
    }

    pub(super) fn from_aes128(k: &crate::crypto::InitialKeys) -> Self {
        // Same shape as `from_initial` — `derive_aes128_keys` and
        // `derive_initial_keys` both return `InitialKeys` post-
        // migration. Kept as a separate method so call sites read
        // cleanly ("post-handshake keys" vs "Initial-stage keys").
        Self::new(&k.key, &k.iv, &k.hp)
    }

    /// Build per-key-phase keys: AEAD `key`/`iv` from the freshly-
    /// derived `next_traffic_secret`, but reuse the existing HP key
    /// (cipher) from `prev`. RFC 9001 §6.1: "the same header
    /// protection key is used" across key phases — only the AEAD
    /// half rotates. Cloning `prev.hp_cipher` avoids re-running
    /// `Aes128::new` for the unchanged HP key.
    pub(super) fn from_aes128_reuse_hp(
        k: &crate::crypto::InitialKeys,
        prev: &DirKeys,
    ) -> Self {
        DirKeys {
            aead_cipher: Aes128Gcm::new(GenericArray::from_slice(&k.key)),
            iv: k.iv,
            hp_cipher: prev.hp_cipher.clone(),
        }
    }

    pub(super) fn aead_seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
    ) -> [u8; TAG_LEN] {
        let tag = self
            .aead_cipher
            .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, data)
            .expect("AES-128-GCM encrypt: infallible for in-range buffers");
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(tag.as_slice());
        out
    }

    pub(super) fn aead_open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), ()> {
        self.aead_cipher
            .decrypt_in_place_detached(
                GenericArray::from_slice(nonce),
                aad,
                data,
                GenericArray::from_slice(tag),
            )
            .map_err(|_| ())
    }

    /// AES-128-ECB on `sample`, truncated to `HP_MASK_LEN` (RFC 9001
    /// §5.4.3). Cipher is pre-keyed; cost per call is one AES block.
    pub(super) fn hp_mask(&self, sample: &[u8; HP_SAMPLE_LEN]) -> [u8; HP_MASK_LEN] {
        let mut block = GenericArray::clone_from_slice(sample);
        self.hp_cipher.encrypt_block(&mut block);
        let mut mask = [0u8; HP_MASK_LEN];
        mask.copy_from_slice(&block[..HP_MASK_LEN]);
        mask
    }
}

// ============================================================================
// Connection: key derivation + key-phase rotation
// ============================================================================

impl Connection {
    /// Promote the next-phase recv keys to current (RFC 9001 §6.1).
    /// Called when a packet's KEY_PHASE bit doesn't match
    /// `recv_key_phase` AND the next-phase keys successfully open
    /// the packet. After rotation the previously-current keys live
    /// in `application_recv_prev` for one more key-phase window so
    /// reordered older packets can still be opened.
    pub(super) fn rotate_recv_keys(&mut self) {
        // current → prev
        self.application_recv_prev = self.application_recv.take();
        // next → current
        self.application_recv = self.application_recv_next.take();
        self.recv_key_phase ^= 1;
        // Derive a fresh next-phase pair from the updated secret.
        if let Some(secret) = self.client_app_secret.as_ref() {
            let next_secret = next_traffic_secret(secret);
            // Save the new "current" secret so the NEXT KU can
            // derive from it.
            self.client_app_secret = Some(next_secret);
            let next_aes128 = derive_aes128_keys(&next_secret);
            // Reuse HP from the new-current keys (HP is invariant
            // across KU per §6.1).
            if let Some(cur) = self.application_recv.as_ref() {
                self.application_recv_next = Some(DirKeys::from_aes128_reuse_hp(&next_aes128, cur));
            }
        }
    }

    pub(super) fn advance_tls(&mut self, config: &TlsServerConfig) -> Result<(), ConnError> {
        let new_state = self.tls.advance(config)?;
        // 0-RTT (early-data) recv keys. Only set on resumption,
        // and only after CH has been parsed — `client_early_traffic_secret()`
        // returns Some at that point. Derived eagerly so we can
        // unprotect 0-RTT packets that arrive in the same datagram
        // as the Initial / right after; without these the packets
        // get silently dropped by `aead_decrypt_failed`.
        if let Some(et) = self.tls.client_early_traffic_secret() {
            if self.early_recv.is_none() {
                let recv = derive_aes128_keys(et);
                self.early_recv = Some(DirKeys::from_aes128(&recv));
                crate::quic_event!(
                    early_keys_derived,
                    "local_cid={}",
                    crate::endpoint::hex8(self.local_cid.as_slice())
                );
                // Replay any 0-RTT packets that arrived before
                // the keys were ready. process_zero_rtt is the
                // canonical handler — call it on each buffered
                // packet so we share decryption + frame-dispatch
                // logic with the steady-state path.
                let pending: Vec<Vec<u8>> = core::mem::take(&mut self.pending_zero_rtt);
                for mut pkt in pending {
                    if let Err(e) = self.process_zero_rtt(&mut pkt) {
                        // Don't propagate — replay failures are
                        // best-effort and shouldn't kill the conn.
                        crate::quic_drop!(other_wire, "0-RTT replay error: {:?}", e);
                    }
                }
            }
        }
        // Once handshake-stage secrets exist on the TLS side and
        // we haven't yet derived our packet-protection keys for
        // the Handshake space, derive them now.
        if let Some(hs) = self.tls.handshake_secrets() {
            if self.handshake_send.is_none() {
                let send = derive_aes128_keys(&hs.server_hs);
                let recv = derive_aes128_keys(&hs.client_hs);
                self.handshake_send = Some(DirKeys::from_aes128(&send));
                self.handshake_recv = Some(DirKeys::from_aes128(&recv));
            }
        }
        if let Some(ap) = self.tls.application_secrets() {
            if self.application_send.is_none() {
                let send = derive_aes128_keys(&ap.server_ap);
                let recv = derive_aes128_keys(&ap.client_ap);
                self.application_send = Some(DirKeys::from_aes128(&send));
                self.application_recv = Some(DirKeys::from_aes128(&recv));
                // Pre-derive next-phase recv keys so a peer-initiated
                // key update (RFC 9001 §6) doesn't require HKDF on
                // the hot decrypt path — we just trial-decrypt with
                // `application_recv_next` whenever the KEY_PHASE bit
                // disagrees with `recv_key_phase`. HP key persists
                // across phases (§6.1: "the same header protection
                // key is used") so we copy it from the current keys.
                self.client_app_secret = Some(ap.client_ap);
                let next_secret = next_traffic_secret(&ap.client_ap);
                let next_aes128 = derive_aes128_keys(&next_secret);
                let cur_recv = self.application_recv.as_ref().unwrap();
                self.application_recv_next =
                    Some(DirKeys::from_aes128_reuse_hp(&next_aes128, cur_recv));
            }
        }
        // `Failed` is terminal — never resurrect it. Without this
        // guard, a peer-initiated CONNECTION_CLOSE (handled in
        // `dispatch_frames` by setting `state = Failed`) is
        // immediately negated by the next `advance_tls` call: TLS
        // is still `Established` (CONNECTION_CLOSE is a transport-
        // level frame, not a TLS-level event), so the block below
        // would set `state = Established` again, bump
        // `handshakes_completed`, and the conn-task's `state ==
        // Failed` break check at the loop tail never fires. Each
        // subsequent inbound datagram (retransmit CLOSE, late ACK,
        // …) repeats the cycle, inflating
        // `handshakes_completed` by hundreds per conn lifecycle.
        if matches!(new_state, QuicTlsState::Established)
            && !matches!(self.state, ConnState::Failed)
        {
            // Edge-trigger the event so a flapping flush_outbound
            // doesn't double-count.
            if !matches!(self.state, ConnState::Established) {
                crate::quic_event!(
                    handshakes_completed,
                    "local_cid={}",
                    crate::endpoint::hex8(self.local_cid.as_slice())
                );
                // If the handshake completed WITHOUT resumption
                // (no early_recv ever derived), we'll never be
                // able to decrypt buffered 0-RTT packets — drop
                // them now so they don't sit in memory until conn
                // teardown. Common when a peer optimistically sent
                // 0-RTT with a stale ticket from a previous boot.
                if !self.pending_zero_rtt.is_empty() && self.early_recv.is_none() {
                    crate::quic_event!(
                        zero_rtt_unresumable,
                        "dropped={} reason=resumption_rejected",
                        self.pending_zero_rtt.len()
                    );
                    self.pending_zero_rtt.clear();
                }
            }
            self.state = ConnState::Established;
            // RFC 9001 §4.9.1 + RFC 9002 §A.5: discard Initial keys
            // belt-and-braces here (the wire path also discards
            // them on first received Handshake packet — see
            // `process_handshake_pkt`). We do NOT discard Handshake
            // keys here even though TLS is Established — the next
            // `flush_outbound` still needs `handshake_send` to emit
            // the ACK for the client's Finished. Handshake keys
            // are discarded later in `process_short_header_packet`
            // on the first successful 1-RTT decrypt: at that point
            // the peer has provably moved on, no more Handshake
            // packets are in flight in either direction, and the
            // RFC 9001 §4.9.2 condition ("handshake is confirmed")
            // is satisfied.
            //
            // The bookkeeping clears here matter independently:
            //   * `time_of_last_ack_eliciting_us[Initial]` is set
            //     when we send our ServerHello and never resets
            //     (Chrome stops sending Initial ACKs as soon as
            //     it derives Handshake keys),
            //   * `pto_deadline_us` picks the smallest deadline
            //     across all spaces, so it stays anchored at
            //     `serverhello_time + pto_period`,
            //   * past that point, PTO fires every loop iteration
            //     until it backs off, throwing PING probes at
            //     idle time.
            if !self.initial_keys_discarded {
                self.initial_keys_discarded = true;
                self.initial_send = None;
                self.initial_recv = None;
            }
            self.initial_space.sent_packets.clear();
            self.initial_space.largest_acked = None;
            self.handshake_space.sent_packets.clear();
            self.handshake_space.largest_acked = None;
            self.time_of_last_ack_eliciting_us[0] = None;
            self.time_of_last_ack_eliciting_us[1] = None;
        } else if matches!(new_state, QuicTlsState::Failed) {
            self.state = ConnState::Failed;
        }
        Ok(())
    }
}
