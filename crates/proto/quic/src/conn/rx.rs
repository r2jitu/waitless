// crates/proto/quic/src/conn/rx.rs — inbound packet processing.
//
// `process_datagram` is the entry point the UDP reactor calls
// per inbound datagram. It walks coalesced packets left-to-right,
// removing each packet's HP + AEAD protection in place, dispatching
// frames into the per-PN-space and per-stream bookkeeping, and
// driving the TLS state machine between packets so key derivations
// from earlier packets are visible to later ones in the same
// datagram. After the walk it drives a full outbound flush so the
// reply (Initial+Handshake during handshake, ACK + STREAM data
// after) ships in the same iteration.

use super::{ConnError, ConnState, Connection, DirKeys, SERVER_CID_LEN};
use crate::crypto::{
    HP_SAMPLE_LEN, TAG_LEN, derive_initial_keys, derive_initial_secrets, packet_nonce,
};
use crate::frame::{Frame, parse_frame};
use crate::tls::CryptoLevel;
use crate::wire::{
    FIXED_BIT, HEADER_FORM_LONG, decode_packet_number, long_packet_type, parse_initial_header,
    parse_long_header_preamble, read_varint,
};
use alloc::vec::Vec;
use tls::TlsServerConfig;

impl Connection {
    /// Process one inbound UDP datagram. Coalesced packets
    /// (Initial+Handshake or Initial+0-RTT in one datagram, both
    /// common with browsers) are walked left-to-right; each packet's
    /// protection is removed independently.
    ///
    /// `advance_tls` runs BETWEEN packets in the loop so that keys
    /// derived from earlier packets (e.g. 0-RTT recv keys derived
    /// when the Initial's ClientHello validates a PSK) are
    /// available to LATER packets in the same datagram. Without
    /// this, the 0-RTT packet that Chrome coalesces with its
    /// Initial would hit `process_zero_rtt` before the CH-driven
    /// `client_early_traffic_secret` is computed, and we'd drop
    /// it with `bad_state: no early_recv keys`. `advance_tls` is
    /// idempotent — `tls.advance` returns once no state change
    /// happens — so calling it per packet is cheap.
    pub fn process_datagram(
        &mut self,
        datagram: &mut [u8],
        config: &TlsServerConfig,
    ) -> Result<(), ConnError> {
        if matches!(self.state, ConnState::Failed) {
            return Ok(());
        }
        // RX-phase cycle bracket (decrypt + dispatch + advance_tls).
        // Closed just before flush_outbound, which is bracketed
        // separately as flush_tx_cycles, so the two don't overlap.
        let rx_start = crate::diag::now_cycles();
        // Refresh the idle-timeout deadline. Any received datagram
        // counts — even one we'll fail to decrypt below — because
        // the peer is clearly still trying. RFC 9000 §10.1 only
        // requires receipt, not successful processing.
        self.last_recv_us = tls::ticket::now_us();
        // Anti-amplification accounting (RFC 9000 §8.1.2): all
        // bytes received from the peer's address count toward our
        // 3× send credit, including ones that fail to decrypt.
        if !self.path_validated {
            self.bytes_received_pre_validation = self
                .bytes_received_pre_validation
                .saturating_add(datagram.len() as u64);
        }
        let mut p = 0usize;
        while p < datagram.len() {
            // Per-packet drop on AEAD failure (RFC 9000 §9.7:
            // endpoints MUST NOT abandon the connection on
            // packets they cannot decrypt). Most common causes:
            //   * a key update we couldn't open with the current or
            //     pre-derived next-phase keys (the common cases ARE
            //     handled — see `rotate_recv_keys` / `rotate_send_keys`).
            //   * stale-keys retransmit straggler.
            //   * unrelated traffic addressed to our DCID.
            // For long-header packets we know the packet length
            // from the header so we can skip exactly that and
            // continue with the next coalesced packet. For
            // short-header (1-RTT) packets there's no length —
            // the packet IS the rest of the datagram — so on
            // decrypt failure we drop the whole remainder.
            //
            // The slice we pass is `&mut datagram[p..]` so each
            // packet processor can do HP-unprotect / AEAD-decrypt
            // in place rather than copying the bytes into a fresh
            // Vec. -1 alloc per inbound packet on the hot path.
            match self.process_one_packet(&mut datagram[p..], config) {
                Ok(0) => break, // forward-progress guard
                Ok(consumed) => {
                    p += consumed;
                }
                Err(ConnError::Decrypt) => {
                    // Stop walking this datagram; conn stays
                    // alive for future packets. Counter was
                    // already bumped via `aead_decrypt_failed`
                    // inside `unprotect_and_decrypt`.
                    break;
                }
                Err(e) => return Err(e),
            }
            // Drive the TLS state machine to derive any new keys
            // before we attempt to decrypt the next coalesced
            // packet. Especially important for Initial → 0-RTT
            // ordering, where 0-RTT decrypt depends on the
            // early-data secret derived from the CH.
            self.advance_tls(config)?;
        }
        // Drive the TLS state machine + queue outbound after
        // consuming all packets in the datagram.
        self.advance_tls(config)?;
        crate::diag::COUNTERS
            .process_rx_cycles
            .add(crate::diag::now_cycles().wrapping_sub(rx_start));
        // Skip the per-datagram flush entirely when it would be a no-op
        // (established, nothing 1-RTT pending — the common case after the
        // delayed ACK leaves a /health request's flush empty). Avoids
        // ~1.5 flush_outbound entries/req, each otherwise re-running
        // apply_peer_flow_control + the full has_one_rtt_to_send scan.
        if !self.flush_outbound_is_noop() {
            crate::diag::COUNTERS.flush_calls.bump();
            self.flush_outbound(config)?;
        }
        self.reap_finished_streams();
        crate::diag::COUNTERS.datagrams_processed.bump();
        Ok(())
    }

    // ── Inbound packet processing ───────────────────────────────

    fn process_one_packet(
        &mut self,
        bytes: &mut [u8],
        _config: &TlsServerConfig,
    ) -> Result<usize, ConnError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let first = bytes[0];
        // QUIC v1 (RFC 9000 §17.3.1) requires bit 6 (FIXED_BIT) set
        // on every long- and short-header packet. A zero (or any
        // byte without FIXED_BIT) at this position is datagram-tail
        // padding — clients pad UDP datagrams to 1200 bytes after
        // the Initial packet's coalesced flight. Consume the rest
        // and stop.
        if first & FIXED_BIT == 0 {
            return Ok(bytes.len());
        }
        if first & HEADER_FORM_LONG != 0 {
            self.process_long_header_packet(bytes)
        } else {
            self.process_short_header_packet(bytes)
        }
    }

    fn process_long_header_packet(&mut self, bytes: &mut [u8]) -> Result<usize, ConnError> {
        let preamble = parse_long_header_preamble(bytes).map_err(|_| {
            crate::quic_drop!(
                long_header_parse,
                "size={} first={:#x}",
                bytes.len(),
                bytes.first().copied().unwrap_or(0)
            );
            ConnError::Wire
        })?;
        match preamble.long_type {
            long_packet_type::INITIAL => self.process_initial(bytes),
            long_packet_type::HANDSHAKE => self.process_handshake_pkt(bytes),
            long_packet_type::ZERO_RTT => self.process_zero_rtt(bytes),
            long_packet_type::RETRY => {
                crate::quic_drop!(other_wire, "RETRY received as server (peer bug)");
                Err(ConnError::Wire)
            }
            _ => {
                crate::quic_drop!(other_wire, "bogus long_type={}", preamble.long_type);
                Err(ConnError::Wire)
            }
        }
    }

    /// 0-RTT (early-data) packet: long-header type=0x01, layout
    /// matches Handshake (no Token field), but encrypted under the
    /// `client_early_traffic_secret`-derived AEAD keys instead of
    /// the handshake-stage ones. Frames inside share the OneRtt
    /// stream namespace per RFC 9001 §5.5 — STREAM frames at
    /// 0-RTT and 1-RTT level are the same logical streams. We
    /// silently drop the packet if `early_recv` is None (no
    /// resumption negotiated), matching the spec's "0-RTT MAY be
    /// rejected; client treats it as transparent retransmission
    /// over 1-RTT" behaviour.
    pub(super) fn process_zero_rtt(&mut self, bytes: &mut [u8]) -> Result<usize, ConnError> {
        let preamble = parse_long_header_preamble(bytes).map_err(|_| {
            crate::quic_drop!(long_header_parse, "0-RTT preamble: size={}", bytes.len());
            ConnError::Wire
        })?;
        let mut p = preamble.tail_offset;
        let (length, n) = read_varint(&bytes[p..]).map_err(|_| ConnError::Wire)?;
        p += n;
        let pn_offset = p;
        let total_packet_len = pn_offset + length as usize;
        if total_packet_len > bytes.len() {
            return Err(ConnError::Wire);
        }
        let recv_keys = match self.early_recv.as_ref() {
            Some(k) => k.clone(),
            None => {
                // Keys aren't ready yet. Buffer the FULL packet
                // (header included) so we can replay it once
                // `advance_tls` derives `early_recv`. This handles:
                //   * 0-RTT coalesced with a multi-packet CH whose
                //     last fragment hasn't arrived yet
                //   * 0-RTT in its own datagram that arrived before
                //     the CH-completing Initial
                // Cap the buffer so a malicious peer can't OOM us
                // by sending undecryptable 0-RTT in a loop. 16
                // packets × ~1500 bytes ≈ 24 KiB/conn worst case.
                const PENDING_ZERO_RTT_CAP: usize = 16;
                if self.pending_zero_rtt.len() < PENDING_ZERO_RTT_CAP {
                    self.pending_zero_rtt
                        .push(bytes[..total_packet_len].to_vec());
                    crate::quic_event!(
                        zero_rtt_buffered,
                        "size={} pending={} local_cid={}",
                        total_packet_len,
                        self.pending_zero_rtt.len(),
                        crate::endpoint::hex8(self.local_cid.as_slice())
                    );
                } else {
                    crate::quic_drop!(
                        bad_state,
                        "0-RTT buffer full ({} packets), dropping new",
                        PENDING_ZERO_RTT_CAP
                    );
                }
                return Ok(total_packet_len);
            }
        };

        let buf = &mut bytes[..total_packet_len];
        let pn = self.unprotect_and_decrypt(buf, pn_offset, &recv_keys)?;
        let pn_length = ((buf[0] & 0x03) as usize) + 1;
        let payload_start = pn_offset + pn_length;
        let payload_end = total_packet_len - TAG_LEN;
        let payload = &buf[payload_start..payload_end];

        // RFC 9001 §5.5: 0-RTT and 1-RTT carry the SAME application
        // data namespace — STREAM frames at 0-RTT belong to the
        // OneRtt stream space. Dispatch under OneRtt so a STREAM
        // frame at 0-RTT followed by a STREAM frame at 1-RTT for
        // the same stream id flows naturally into one RecvStream.
        self.dispatch_frames(CryptoLevel::OneRtt, payload)?;

        // ACKs for 0-RTT live in the application_space PN ring
        // alongside 1-RTT ACKs (RFC 9000 §17.2.3).
        self.application_space.record_recv_pn(pn);
        self.note_app_ack_eliciting();
        crate::quic_event!(
            zero_rtt_accepted,
            "pn={} payload_len={} local_cid={}",
            pn,
            payload_end - payload_start,
            crate::endpoint::hex8(self.local_cid.as_slice())
        );
        Ok(total_packet_len)
    }

    fn process_initial(&mut self, bytes: &mut [u8]) -> Result<usize, ConnError> {
        // Parse the header up-front, copying out everything we'll
        // need afterwards (pn_offset + total_packet_len), so the
        // immutable borrow on `bytes` ends before we reborrow it
        // mutably for in-place HP/AEAD work.
        let (header_pn_offset, total_packet_len) = {
            let header = parse_initial_header(bytes).map_err(|_| ConnError::Wire)?;
            // Late retransmit Initial after we've already discarded
            // Initial keys (RFC 9001 §4.9.1). Skip past it; both
            // sides have moved on, the peer's PN ACK accounting
            // doesn't need this one re-acked.
            if self.initial_keys_discarded {
                let total = header.pn_offset + header.length as usize;
                if total > bytes.len() {
                    return Err(ConnError::Wire);
                }
                crate::quic_event!(
                    late_initial_dropped,
                    "size={} dcid={}",
                    total,
                    crate::endpoint::hex8(header.preamble.dcid)
                );
                return Ok(total);
            }
            if self.initial_recv.is_none() {
                let dcid = super::ConnectionId::new(header.preamble.dcid);
                let scid = super::ConnectionId::new(header.preamble.scid);
                self.initial_dcid = dcid;
                self.peer_cid = scid;
                let secrets = derive_initial_secrets(self.initial_dcid.as_slice());
                let server_keys = derive_initial_keys(&secrets.server);
                let client_keys = derive_initial_keys(&secrets.client);
                self.initial_send = Some(DirKeys::from_initial(&server_keys));
                self.initial_recv = Some(DirKeys::from_initial(&client_keys));
                self.state = ConnState::Connecting;
                let server_params = {
                    let p = crate::transport_params::ServerParams::defaults(
                        self.initial_dcid.as_slice(),
                        self.local_cid.as_slice(),
                    );
                    let mut blob = Vec::with_capacity(64);
                    p.encode(&mut blob);
                    blob
                };
                self.tls.set_server_transport_params(server_params);
            }
            (header.pn_offset, header.pn_offset + header.length as usize)
        };
        if total_packet_len > bytes.len() {
            return Err(ConnError::Wire);
        }
        let recv_keys = self
            .initial_recv
            .as_ref()
            .ok_or(ConnError::BadState)?
            .clone();

        let buf = &mut bytes[..total_packet_len];
        let pn = self.unprotect_and_decrypt(buf, header_pn_offset, &recv_keys)?;

        // Frame parsing: payload = buf[pn_offset + pn_length .. end - TAG_LEN].
        // unprotect_and_decrypt set buf[pn_offset..pn_offset+pn_length]
        // to the unprotected PN. We need pn_length to find payload start.
        let pn_length = ((buf[0] & 0x03) as usize) + 1;
        let payload_start = header_pn_offset + pn_length;
        let payload_end = total_packet_len - TAG_LEN;
        let payload = &buf[payload_start..payload_end];
        self.dispatch_frames(CryptoLevel::Initial, payload)?;

        self.initial_space.record_recv_pn(pn);
        self.initial_space.ack_pending = true;
        Ok(total_packet_len)
    }

    fn process_handshake_pkt(&mut self, bytes: &mut [u8]) -> Result<usize, ConnError> {
        // Handshake packet shares the long-header preamble shape
        // with Initial but has no Token field — just Length.
        let preamble = parse_long_header_preamble(bytes).map_err(|_| ConnError::Wire)?;
        let mut p = preamble.tail_offset;
        let (length, n) = read_varint(&bytes[p..]).map_err(|_| ConnError::Wire)?;
        p += n;
        let pn_offset = p;
        let total_packet_len = pn_offset + length as usize;
        if total_packet_len > bytes.len() {
            return Err(ConnError::Wire);
        }
        // Late retransmit Handshake after we've discarded our
        // Handshake keys (RFC 9001 §4.9.2 — TLS handshake
        // confirmed). Skip past it; counterpart of the late-Initial
        // path in `process_initial`.
        if self.handshake_keys_discarded {
            crate::quic_event!(
                late_handshake_dropped,
                "size={} dcid={}",
                total_packet_len,
                crate::endpoint::hex8(preamble.dcid)
            );
            return Ok(total_packet_len);
        }

        let recv_keys = self
            .handshake_recv
            .as_ref()
            .ok_or(ConnError::BadState)?
            .clone();

        let buf = &mut bytes[..total_packet_len];
        let pn = self.unprotect_and_decrypt(buf, pn_offset, &recv_keys)?;
        let pn_length = ((buf[0] & 0x03) as usize) + 1;
        let payload_start = pn_offset + pn_length;
        let payload_end = total_packet_len - TAG_LEN;
        let payload = &buf[payload_start..payload_end];
        self.dispatch_frames(CryptoLevel::Handshake, payload)?;

        // RFC 9001 §4.9.1: a successfully-decrypted Handshake packet
        // from the peer means both sides have moved past Initial.
        // Discard Initial keys so straggler Initial retransmits fall
        // through to `late_initial_dropped` instead of attempting
        // AEAD against stale state. Edge-trigger via the
        // `initial_keys_discarded` flag so the inner `is_none()`
        // check in `process_initial` doesn't re-derive keys for a
        // late Initial.
        if !self.initial_keys_discarded {
            self.initial_keys_discarded = true;
            self.initial_send = None;
            self.initial_recv = None;
            // Bookkeeping for the now-defunct PN space — these are
            // also cleared by the TLS-Established hook later, but
            // doing them eagerly here is cheap and keeps state
            // consistent with the "Initial is gone" invariant.
            self.discard_sent_packets(crate::tls::CryptoLevel::Initial);
            self.initial_space.largest_acked = None;
            self.time_of_last_ack_eliciting_us[0] = None;
        }

        self.handshake_space.record_recv_pn(pn);
        self.handshake_space.ack_pending = true;
        // RFC 9000 §8.1: a successful Handshake-encrypted packet
        // proves the peer holds the source address (they had to
        // decrypt our ServerHello to derive Handshake keys). The
        // 3× anti-amplification limit is lifted from now on.
        self.path_validated = true;
        Ok(total_packet_len)
    }

    fn process_short_header_packet(&mut self, bytes: &mut [u8]) -> Result<usize, ConnError> {
        // Short-header (1-RTT) layout:
        //   u8 first byte || N-byte DCID || PN bytes || ciphertext || tag.
        // DCID length is endpoint-known. For our server it's
        // always SERVER_CID_LEN — the connection pool routed this
        // datagram to us by matching that prefix.
        if bytes.len() < 1 + SERVER_CID_LEN + 4 + TAG_LEN {
            return Err(ConnError::Wire);
        }
        let pn_offset = 1 + SERVER_CID_LEN;

        // Short-header packets aren't length-prefixed inside the
        // datagram — every byte until the end is one packet for us
        // (no coalescing post-handshake in QUIC v1; receivers MUST
        // process the whole thing).
        let total_packet_len = bytes.len();

        // Key-update aware decryption (RFC 9001 §6).
        //
        // 1. HP unprotect with whichever set of keys; HP keys
        //    persist across phases so any of {prev, current, next}
        //    works — we use `application_recv` since it's always
        //    present once the handshake completes.
        // 2. After HP unprotect, the first byte's bit 2 (KEY_PHASE)
        //    tells us which AEAD keys protect this packet.
        // 3. If KP matches `recv_key_phase` → AEAD-open with
        //    `application_recv`. The common path.
        // 4. If KP differs → trial-decrypt with
        //    `application_recv_next`. On success, peer initiated
        //    a key update: rotate (prev <- current; current <- next;
        //    derive new next from updated client_app_secret) and
        //    flip `recv_key_phase`. This is the path that today
        //    fails silently — without it, every post-update
        //    packet AEAD-fails forever.
        // 5. If trial-decrypt with _next ALSO fails, the packet
        //    might be a reordered straggler from BEFORE the last
        //    update we already processed — try `application_recv_prev`
        //    (which holds the previous-phase keys for one rotation).
        //
        // The header-protection step only happens once; the AEAD
        // attempts share the unprotected first byte / PN bytes.
        let recv_keys_cur = self
            .application_recv
            .as_ref()
            .ok_or(ConnError::BadState)?
            .clone();
        let buf = &mut bytes[..total_packet_len];
        let pn = self.unprotect_header(buf, pn_offset, &recv_keys_cur)?;
        let pn_length = ((buf[0] & 0x03) as usize) + 1;
        let payload_start = pn_offset + pn_length;
        let payload_end = total_packet_len - TAG_LEN;
        if payload_end < payload_start {
            return Err(ConnError::Wire);
        }
        let pkt_kp = (buf[0] & 0x04) >> 2;

        // Try the keys appropriate for this packet's KP. Split `buf`
        // into two disjoint mutable slices: AAD is the unprotected
        // header bytes, payload+tag the rest. Avoids the per-packet
        // `to_vec()` of the header — for `/diagnostics` over a kept-
        // alive QUIC conn that meant 3-6 fewer allocs per refresh.
        // Same approach the Initial/Handshake path already uses
        // (see `decrypt_long_header`).
        let nonce = packet_nonce(&recv_keys_cur.iv, pn);
        let tag: [u8; TAG_LEN] = buf[payload_end..].try_into().map_err(|_| ConnError::Wire)?;
        let (aad_part, rest_part) = buf.split_at_mut(payload_start);
        let aad: &[u8] = aad_part;
        let payload_slice = &mut rest_part[..payload_end - payload_start];

        let aead_result = if pkt_kp == self.recv_key_phase {
            recv_keys_cur.aead_open(&nonce, aad, payload_slice, &tag)
        } else if let Some(next) = self.application_recv_next.as_ref().cloned() {
            // Peer's KP differs from ours: try the next-phase keys.
            let next_nonce = packet_nonce(&next.iv, pn);
            match next.aead_open(&next_nonce, aad, payload_slice, &tag) {
                Ok(()) => {
                    // Successful key update — rotate and re-derive.
                    self.rotate_recv_keys();
                    crate::quic_event!(
                        key_updates_accepted,
                        "new_phase={} pn={}",
                        self.recv_key_phase,
                        pn
                    );
                    Ok(())
                }
                Err(()) => {
                    // Try previous-phase keys for reorder absorption.
                    if let Some(prev) = self.application_recv_prev.as_ref() {
                        let prev_nonce = packet_nonce(&prev.iv, pn);
                        prev.aead_open(&prev_nonce, aad, payload_slice, &tag)
                    } else {
                        Err(())
                    }
                }
            }
        } else {
            // No next-phase keys yet (shouldn't happen post-handshake)
            // — try previous-phase as a last resort.
            if let Some(prev) = self.application_recv_prev.as_ref() {
                let prev_nonce = packet_nonce(&prev.iv, pn);
                prev.aead_open(&prev_nonce, aad, payload_slice, &tag)
            } else {
                Err(())
            }
        };
        aead_result.map_err(|_| {
            crate::quic_drop!(
                aead_decrypt_failed,
                "1-RTT pn={} kp={} our_kp={} payload_len={}",
                pn,
                pkt_kp,
                self.recv_key_phase,
                payload_end - payload_start
            );
            ConnError::Decrypt
        })?;
        crate::diag::COUNTERS
            .aead_open_bytes
            .add((payload_end - payload_start) as u64);
        crate::diag::COUNTERS.aead_open_packets.bump();

        let payload = &buf[payload_start..payload_end];
        self.dispatch_frames(CryptoLevel::OneRtt, payload)?;

        // RFC 9001 §4.9.2: a successfully-decrypted 1-RTT packet
        // confirms the TLS handshake from the receiver's side
        // (peer used 1-RTT keys we wouldn't have if Finished
        // hadn't completed). Discard Handshake keys so straggler
        // Handshake retransmits fall through to
        // `late_handshake_dropped`. Edge-trigger via the flag —
        // covers the case where the existing TLS-Established hook
        // hasn't fired yet (it only fires when our TLS state
        // advances; but the peer can send a 1-RTT packet
        // earlier — coalesced with their Finished).
        if !self.handshake_keys_discarded {
            self.handshake_keys_discarded = true;
            self.handshake_send = None;
            self.handshake_recv = None;
            self.discard_sent_packets(crate::tls::CryptoLevel::Handshake);
            self.handshake_space.largest_acked = None;
            self.time_of_last_ack_eliciting_us[1] = None;
        }

        self.application_space.record_recv_pn(pn);
        self.note_app_ack_eliciting();
        Ok(total_packet_len)
    }

    /// Remove header protection in place (no AEAD). Returns the
    /// reconstructed full PN. Used by the 1-RTT path which then
    /// trial-decrypts with one of three key-phase key sets;
    /// Initial/Handshake stick with `unprotect_and_decrypt` since
    /// they have no key-phase ambiguity.
    fn unprotect_header(
        &self,
        buf: &mut [u8],
        pn_offset: usize,
        keys: &DirKeys,
    ) -> Result<u64, ConnError> {
        let sample_start = pn_offset + 4;
        if sample_start + HP_SAMPLE_LEN > buf.len() {
            return Err(ConnError::Wire);
        }
        let mut sample = [0u8; HP_SAMPLE_LEN];
        sample.copy_from_slice(&buf[sample_start..sample_start + HP_SAMPLE_LEN]);
        let mask = keys.hp_mask(&sample);

        let is_long = buf[0] & HEADER_FORM_LONG != 0;
        buf[0] ^= mask[0] & if is_long { 0x0f } else { 0x1f };
        let pn_length = ((buf[0] & 0x03) as usize) + 1;
        if pn_length > 4 || pn_offset + pn_length + TAG_LEN > buf.len() {
            return Err(ConnError::Wire);
        }
        for i in 0..pn_length {
            buf[pn_offset + i] ^= mask[1 + i];
        }
        let mut truncated = 0u64;
        for i in 0..pn_length {
            truncated = (truncated << 8) | buf[pn_offset + i] as u64;
        }
        let space = if is_long {
            let lt = (buf[0] >> 4) & 0x3;
            match lt {
                long_packet_type::INITIAL => &self.initial_space,
                long_packet_type::HANDSHAKE => &self.handshake_space,
                _ => &self.application_space,
            }
        } else {
            &self.application_space
        };
        let largest = space.largest_recv_pn.unwrap_or(0u64.wrapping_sub(1));
        Ok(decode_packet_number(largest, truncated, pn_length))
    }

    /// Remove header protection AND open the AEAD on a complete
    /// packet buffer in place. Returns the reconstructed full PN.
    /// `buf` enters as: protected first byte, protected PN bytes,
    /// ciphertext, tag. Exits as: unprotected first byte, PN
    /// bytes, decrypted plaintext (tag verified, then discarded).
    pub(super) fn unprotect_and_decrypt(
        &self,
        buf: &mut [u8],
        pn_offset: usize,
        keys: &DirKeys,
    ) -> Result<u64, ConnError> {
        // HP sample is 16 bytes starting at pn_offset + 4.
        let sample_start = pn_offset + 4;
        if sample_start + HP_SAMPLE_LEN > buf.len() {
            return Err(ConnError::Wire);
        }
        let mut sample = [0u8; HP_SAMPLE_LEN];
        sample.copy_from_slice(&buf[sample_start..sample_start + HP_SAMPLE_LEN]);
        let mask = keys.hp_mask(&sample);

        // Determine if it's a long-header packet from the protected
        // first byte's top two bits — those are HP-untouched per
        // RFC 9001 §5.4.1 (only low 4/5 bits get masked).
        let is_long = buf[0] & HEADER_FORM_LONG != 0;
        // Two-step HP unprotect (RFC 9001 §5.4.1):
        //   1. XOR mask[0] (low 4 or 5 bits) into the first byte.
        //   2. Read pn_length from the now-unmasked first byte.
        //   3. XOR mask[1 .. 1+pn_length] into exactly the PN bytes.
        // Doing all 4 PN-window bytes up-front would over-XOR the
        // (4 − pn_length) bytes that aren't PN — those are
        // ciphertext, and the corruption breaks AEAD verification.
        buf[0] ^= mask[0] & if is_long { 0x0f } else { 0x1f };
        let pn_length = ((buf[0] & 0x03) as usize) + 1;
        if pn_length > 4 || pn_offset + pn_length + TAG_LEN > buf.len() {
            return Err(ConnError::Wire);
        }
        for i in 0..pn_length {
            buf[pn_offset + i] ^= mask[1 + i];
        }
        // The truncated PN is the first `pn_length` bytes after pn_offset.
        let mut truncated = 0u64;
        for i in 0..pn_length {
            truncated = (truncated << 8) | buf[pn_offset + i] as u64;
        }
        // Reconstruct against the largest seen PN in this space.
        let space = match buf[0] & 0xc0 {
            // Initial = type 00 in long header (0xc0..0xcf range)
            x if x & HEADER_FORM_LONG != 0 => {
                let lt = (buf[0] >> 4) & 0x3;
                match lt {
                    long_packet_type::INITIAL => &self.initial_space,
                    long_packet_type::HANDSHAKE => &self.handshake_space,
                    _ => &self.application_space,
                }
            }
            _ => &self.application_space,
        };
        let largest = space.largest_recv_pn.unwrap_or(0u64.wrapping_sub(1));
        let full_pn = decode_packet_number(largest, truncated, pn_length);

        // AEAD AAD = unprotected header bytes (everything before
        // ciphertext): buf[..pn_offset + pn_length]. Avoid the
        // alloc by splitting `buf` into disjoint mutable slices
        // — the AAD prefix becomes a borrow of one half, the
        // payload+tag a borrow of the other.
        let aad_end = pn_offset + pn_length;
        let payload_end = buf.len() - TAG_LEN;
        let tag: [u8; TAG_LEN] = buf[payload_end..].try_into().map_err(|_| ConnError::Wire)?;
        let nonce = packet_nonce(&keys.iv, full_pn);
        let (aad_part, rest_part) = buf.split_at_mut(aad_end);
        let aad: &[u8] = aad_part;
        let payload_slice = &mut rest_part[..payload_end - aad_end];
        keys.aead_open(&nonce, aad, payload_slice, &tag)
            .map_err(|_| {
                crate::quic_drop!(
                    aead_decrypt_failed,
                    "pn={} payload_len={}",
                    full_pn,
                    payload_end - aad_end
                );
                ConnError::Decrypt
            })?;
        Ok(full_pn)
    }

    pub(super) fn dispatch_frames(
        &mut self,
        level: CryptoLevel,
        mut payload: &[u8],
    ) -> Result<(), ConnError> {
        while !payload.is_empty() {
            let (frame, consumed) = parse_frame(payload).map_err(|e| {
                crate::quic_drop!(
                    unknown_frame,
                    "level={:?} err={:?} first={:#x} rem={}",
                    level,
                    e,
                    payload[0],
                    payload.len()
                );
                ConnError::Wire
            })?;
            match frame {
                Frame::Padding | Frame::Ping => {}
                Frame::Crypto { offset, data } => {
                    self.tls.push_handshake(level, offset, data);
                }
                Frame::Ack {
                    largest_acknowledged,
                    ack_delay,
                    first_ack_range,
                    ack_ranges,
                    ..
                } => {
                    self.process_ack(
                        level,
                        largest_acknowledged,
                        ack_delay,
                        first_ack_range,
                        ack_ranges,
                    );
                }
                Frame::ConnectionCloseTransport {
                    error_code,
                    frame_type,
                    reason,
                } => {
                    // Principle 4: capture the peer's close detail
                    // rather than discarding it via `{ .. }`. The
                    // error_code / frame_type / reason land in
                    // `LAST_CONN_CLOSE` for `/quic_stats`.
                    crate::diag::record_conn_close(false, error_code, frame_type, reason);
                    self.state = ConnState::Failed;
                    return Ok(());
                }
                Frame::ConnectionCloseApplication { error_code, reason } => {
                    // Application close (0x1d) carries no frame_type.
                    crate::diag::record_conn_close(true, error_code, 0, reason);
                    self.state = ConnState::Failed;
                    return Ok(());
                }
                Frame::HandshakeDone => {
                    // Server only — clients don't send this.
                }
                Frame::Stream {
                    stream_id,
                    offset,
                    data,
                    fin,
                } => {
                    if matches!(level, CryptoLevel::OneRtt) {
                        // Late STREAM-frame retransmit for a stream
                        // we've already finished and reaped: drop
                        // the bytes on the floor. Resurrecting
                        // recv_stream + re-pushing to opened_streams
                        // would only let `reap_finished_streams`
                        // immediately re-kill the entry (the
                        // matching send_stream still satisfies the
                        // reap conditions on its way out), and the
                        // H3 server would block forever on the
                        // resurrected sid. The peer's own ACK + FIN
                        // bookkeeping is already complete, so
                        // discarding here is safe.
                        if self.is_reaped(stream_id) {
                            // Note: the application_space.ack_pending
                            // bump below also fires for already-
                            // reaped streams so the peer sees an
                            // ACK and stops retransmitting.
                            self.note_app_ack_eliciting();
                            payload = &payload[consumed..];
                            continue;
                        }
                        let was_new = !self.recv_streams.contains_key(&stream_id);
                        // Read before the &mut borrow below — the
                        // datagram arrival time the conn task stamped
                        // for this `process_datagram` pass.
                        let cur_rx_us = self.cur_rx_us;
                        if was_new {
                            // RFC 9000 §4.6: a peer-initiated stream id
                            // past the MAX_STREAMS limit we advertised is
                            // a STREAM_LIMIT_ERROR. `count` is how many
                            // streams of this type the id implies (ids
                            // step by 4; low 2 bits = initiator+type).
                            // Without this a peer can send STREAM frames
                            // for arbitrary high ids and grow
                            // `recv_streams` unbounded → heap OOM. Plus a
                            // concurrency backstop: the advertised limit
                            // climbs with the peer's monotonic stream
                            // high-watermark (tx::append_max_streams_into),
                            // so enforcing it alone wouldn't bound a peer
                            // that opens streams and never closes them. A
                            // legit peer finishes streams (removed in
                            // `reap_finished_streams`) so its LIVE count
                            // stays small — far under this cap; a peer
                            // holding thousands open is the attack.
                            if exceeds_stream_limit(
                                stream_id,
                                self.peer_max_streams_bidi_advertised,
                                self.peer_max_streams_uni_advertised,
                                self.recv_streams.len(),
                            ) {
                                crate::diag::COUNTERS.stream_limit_exceeded.bump();
                                crate::quic_drop!(
                                    other_wire,
                                    "stream limit: sid={} bidi_adv={} uni_adv={} live={}",
                                    stream_id,
                                    self.peer_max_streams_bidi_advertised,
                                    self.peer_max_streams_uni_advertised,
                                    self.recv_streams.len()
                                );
                                self.close_with_error(
                                    0x04, /* STREAM_LIMIT_ERROR */
                                    b"stream limit",
                                );
                                return Ok(());
                            }
                            // Pull from the per-conn recycle pool so
                            // a recycled stream's `buffer` Vec keeps
                            // its capacity across stream lifecycles
                            // (saves the first-`extend_from_slice`
                            // allocation per request stream on the
                            // H3 hot path).
                            let new_stream = self
                                .recv_pool
                                .pop()
                                .unwrap_or_default();
                            self.recv_streams.insert(stream_id, new_stream);
                        }
                        let s = self.recv_streams.get_mut(&stream_id).unwrap();
                        if was_new {
                            // Stamp arrival time so the request RX→TX
                            // latency can be sampled when the matching
                            // response stream FINs (see `streams.rs`).
                            s.rx_us = cur_rx_us;
                        }
                        // ── Receive flow control (RFC 9000 §4.1) ──────
                        // Reject any byte past the per-stream
                        // MAX_STREAM_DATA (`recv_max`) or connection
                        // MAX_DATA (`max_data_advertised`) limits we
                        // advertised, BEFORE ingest: the contiguous
                        // append in `RecvStream::ingest` is otherwise
                        // unbounded, so a peer that ignores the window
                        // could grow our recv buffer until the heap is
                        // exhausted. `recv_high` is this stream's largest
                        // received offset; `data_received` sums them
                        // across the connection. A compliant peer never
                        // exceeds the window it was granted, so this
                        // never fires on the happy path.
                        let frame_end = offset.saturating_add(data.len() as u64);
                        let recv_max = s.recv_max;
                        let conn_delta = frame_end.saturating_sub(s.recv_high);
                        if frame_end > recv_max
                            || self.data_received.saturating_add(conn_delta)
                                > self.max_data_advertised
                        {
                            crate::quic_drop!(
                                other_wire,
                                "recv flow control: sid={} end={} recv_max={} received={} max_data={}",
                                stream_id,
                                frame_end,
                                recv_max,
                                self.data_received,
                                self.max_data_advertised
                            );
                            self.close_with_error(0x03 /* FLOW_CONTROL_ERROR */, b"flow control");
                            return Ok(());
                        }
                        self.data_received = self.data_received.saturating_add(conn_delta);
                        // Track the newly-buffered bytes in the global
                        // aggregate recv budget (#75 admission control).
                        super::recv_buffered_add(conn_delta);
                        let s = self.recv_streams.get_mut(&stream_id).unwrap();
                        if frame_end > s.recv_high {
                            s.recv_high = frame_end;
                        }
                        s.ingest(offset, data, fin);
                        if was_new {
                            crate::diag::COUNTERS.recv_streams_created.bump();
                            // Update the peer-stream-count high
                            // watermark per type. Stream IDs encode
                            // (initiator, type) in the low 2 bits:
                            //   00 = client bidi, 01 = server bidi,
                            //   02 = client uni,  03 = server uni.
                            // We only see client-initiated here.
                            let count = (stream_id >> 2) + 1;
                            match stream_id & 0x3 {
                                0x0 => {
                                    if count > self.peer_bidi_streams_opened {
                                        self.peer_bidi_streams_opened = count;
                                    }
                                }
                                0x2 => {
                                    if count > self.peer_uni_streams_opened {
                                        self.peer_uni_streams_opened = count;
                                    }
                                }
                                _ => {}
                            }
                        }
                        // Push to `opened_streams` semantics depend
                        // on the stream type (RFC 9000 §2.1, low 2
                        // bits of sid):
                        //
                        //   0x0 client bidi → request stream. Push
                        //        ONLY on `was_new`; the H3 handler
                        //        consumes data via `recv()` on the
                        //        existing recv_stream and a re-push
                        //        would let `accept_stream` re-yield
                        //        a sid the handler has already
                        //        finished, stranding it in `recv()`.
                        //   0x2 client uni → control / QPACK
                        //        encoder / QPACK decoder. The H3
                        //        server uses re-yield as a periodic
                        //        signal to call `discard_recv` and
                        //        reset the recv buffer; without
                        //        re-push, QPACK update bytes
                        //        accumulate forever on a long-
                        //        lived conn (real leak for
                        //        Chrome's refresh pattern).
                        //   0x1 / 0x3 server-initiated → we don't
                        //        open these; if the peer somehow
                        //        sends one, conservatively use the
                        //        bidi rule.
                        let push = if stream_id & 0x3 == 0x2 {
                            !self.opened_streams.contains(&stream_id)
                        } else {
                            was_new
                        };
                        if push {
                            self.opened_streams.push(stream_id);
                        }
                        // Best-effort STREAM-level ack pending so we
                        // schedule a 1-RTT ACK for it on the next
                        // outbound flush.
                        self.note_app_ack_eliciting();
                    }
                }
                Frame::MaxData { maximum } => {
                    // Peer raised our connection-level send limit
                    // (RFC 9000 §4.1). Flow-control limits are
                    // monotonic; `max` ignores reordered / stale frames.
                    self.peer_max_data = self.peer_max_data.max(maximum);
                }
                Frame::MaxStreamData { stream_id, maximum } => {
                    // Peer raised a stream's send limit. The common h3
                    // case: the client extends the window as it consumes
                    // our response. Apply only if the send stream exists;
                    // otherwise the initial-param seed stands.
                    if let Some(s) = self.send_streams.get_mut(&stream_id) {
                        s.peer_max_stream_data = s.peer_max_stream_data.max(maximum);
                    }
                }
                Frame::PathChallenge { data } => {
                    // RFC 9000 §8.2.2: MUST echo the data in a
                    // PATH_RESPONSE. Queue it for the next 1-RTT flush;
                    // a fresh challenge supersedes an unsent one.
                    self.pending_path_response = Some(data);
                }
                Frame::Skipped { kind } => {
                    // Most wire-recognized frames need no app-level
                    // reaction (NEW_CONNECTION_ID, …); the
                    // frame layer already consumed the right bytes. But
                    // DATA_BLOCKED / STREAM_DATA_BLOCKED / STREAMS_BLOCKED
                    // mean the peer is stalled at a flow-control or
                    // stream-limit edge — force the next packet (this
                    // datagram's post-dispatch flush) to re-advertise the
                    // current limit so a MAX_* the peer lost is recovered
                    // (we don't retransmit those frames per se).
                    match kind {
                        crate::frame::ftype::DATA_BLOCKED => self.force_max_data = true,
                        crate::frame::ftype::STREAM_DATA_BLOCKED => {
                            self.force_max_stream_data = true;
                        }
                        crate::frame::ftype::STREAMS_BLOCKED_BIDI => {
                            self.force_max_streams_bidi = true;
                        }
                        crate::frame::ftype::STREAMS_BLOCKED_UNI => {
                            self.force_max_streams_uni = true;
                        }
                        _ => {}
                    }
                }
            }
            payload = &payload[consumed..];
        }
        Ok(())
    }
}

/// Largest number of concurrently-live peer-initiated recv streams a
/// connection will hold. Far above any real client's concurrency
/// (browsers cap at ~100-256) yet bounds the `recv_streams` map: the
/// advertised MAX_STREAMS limit climbs with the peer's monotonic
/// stream high-watermark, so it alone cannot stop a peer that opens
/// streams and never closes them.
const MAX_CONCURRENT_RECV_STREAMS: usize = 8192;

/// Should a newly-seen peer-initiated `stream_id` be rejected
/// (RFC 9000 §4.6 `STREAM_LIMIT_ERROR`)? Pure decision so it is
/// exhaustively unit-testable apart from the connection state.
///
/// * `bidi_adv` / `uni_adv` — the MAX_STREAMS *counts* (not ids) we
///   have advertised for client-bidi / client-uni streams.
/// * `live` — current `recv_streams` map size (the concurrency
///   backstop).
///
/// A stream id encodes `(initiator, type)` in its low 2 bits and
/// steps by 4, so id `4*(k-1)+kind` is the k-th stream of its kind:
/// `count = (id >> 2) + 1`. Reject when `count` exceeds the advertised
/// limit for that kind, or when the live map is already at the cap.
/// Server-initiated ids (0x1 / 0x3) get a 0 limit — we never grant the
/// peer credit to open those, so any such id is rejected.
fn exceeds_stream_limit(stream_id: u64, bidi_adv: u64, uni_adv: u64, live: usize) -> bool {
    let count = (stream_id >> 2) + 1;
    let limit = match stream_id & 0x3 {
        0x0 => bidi_adv,
        0x2 => uni_adv,
        _ => 0,
    };
    count > limit || live >= MAX_CONCURRENT_RECV_STREAMS
}

#[cfg(test)]
mod stream_limit_tests {
    use super::{exceeds_stream_limit, MAX_CONCURRENT_RECV_STREAMS};

    // Stream-id kinds (low 2 bits): 0x0 client-bidi, 0x1 server-bidi,
    // 0x2 client-uni, 0x3 server-uni.
    const ADV: u64 = 1024; // a typical advertised limit per kind.

    #[test]
    fn within_advertised_limit_is_allowed() {
        // k-th client-bidi stream id = 4*(k-1). The 1024th (count
        // 1024 == ADV) is the last allowed; everything below passes.
        assert!(!exceeds_stream_limit(0, ADV, ADV, 0)); // 1st
        assert!(!exceeds_stream_limit(4 * 1023, ADV, ADV, 0)); // 1024th, count==ADV
        // client-uni (0x2): ids 2, 6, 10, ...
        assert!(!exceeds_stream_limit(2, ADV, ADV, 0));
        assert!(!exceeds_stream_limit(4 * 1023 + 2, ADV, ADV, 0)); // 1024th uni
    }

    #[test]
    fn one_past_advertised_limit_is_rejected() {
        // count == ADV+1 → rejected for each client-initiated kind.
        assert!(exceeds_stream_limit(4 * 1024, ADV, ADV, 0)); // 1025th bidi
        assert!(exceeds_stream_limit(4 * 1024 + 2, ADV, ADV, 0)); // 1025th uni
    }

    #[test]
    fn huge_stream_id_is_rejected_without_allocation() {
        // The instant-OOM attack: one STREAM frame with an enormous
        // id. count is astronomically over any limit → rejected before
        // a map entry is ever created.
        let huge = 1u64 << 60;
        assert!(exceeds_stream_limit(huge, ADV, ADV, 0));
        assert!(exceeds_stream_limit(huge | 0x2, ADV, ADV, 0)); // uni variant
    }

    #[test]
    fn server_initiated_ids_are_always_rejected() {
        // We never grant the peer credit to open server-initiated
        // streams (0x1 server-bidi, 0x3 server-uni); any such id, even
        // the very first, is a protocol violation.
        assert!(exceeds_stream_limit(0x1, ADV, ADV, 0)); // 1st server-bidi
        assert!(exceeds_stream_limit(0x3, ADV, ADV, 0)); // 1st server-uni
    }

    #[test]
    fn concurrency_backstop_rejects_when_map_full() {
        // Even a low, in-limit id is rejected once the live map is at
        // the cap — the open-and-hold attack the advertised limit
        // (which climbs with the watermark) cannot stop on its own.
        assert!(exceeds_stream_limit(0, u64::MAX, u64::MAX, MAX_CONCURRENT_RECV_STREAMS));
        // One below the cap still passes (id 0 within an infinite adv).
        assert!(!exceeds_stream_limit(
            0,
            u64::MAX,
            u64::MAX,
            MAX_CONCURRENT_RECV_STREAMS - 1
        ));
    }

    #[test]
    fn uni_and_bidi_limits_are_independent() {
        // A generous bidi limit must not let an over-limit uni id
        // through, and vice-versa.
        assert!(exceeds_stream_limit(4 * 10 + 2, /*bidi*/ u64::MAX, /*uni*/ 5, 0));
        assert!(exceeds_stream_limit(4 * 10, /*bidi*/ 5, /*uni*/ u64::MAX, 0));
    }
}
