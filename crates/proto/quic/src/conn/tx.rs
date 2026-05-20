// crates/proto/quic/src/conn/tx.rs — outbound packet assembly + seal.
//
// `flush_outbound` is the orchestrator: it coalesces an Initial,
// Handshake, and first 1-RTT packet into a single datagram and
// then drains any remaining 1-RTT data into additional datagrams
// (each its own UDP packet — RFC 9000 §12.2 forbids coalescing
// short-header packets). The per-level `encode_*_packet` helpers
// write directly into the datagram buffer to avoid extra memcpys.
// `seal_packet` applies AEAD + HP protection in place.
//
// `close_with_error` / `flush_close` / `encode_close_packet` form
// the CONNECTION_CLOSE path; `encode_ping_probe` backs the PTO
// timer in `loss.rs`.

use super::{ConnError, ConnState, Connection, SpaceState, append_max_streams_into};
use crate::crypto::{HP_SAMPLE_LEN, TAG_LEN, apply_hp_mask, packet_nonce};
use crate::frame::{write_ack, write_crypto};
use crate::tls::CryptoLevel;
use crate::wire::{FIXED_BIT, QUIC_VERSION_1, write_varint};
use alloc::vec;
use alloc::vec::Vec;
use tls::TlsServerConfig;

impl Connection {
    /// Schedule a CONNECTION_CLOSE on the next outbound flush.
    /// Per RFC 9000 §10.2 the close is emitted as a single packet
    /// at the highest level we have keys for; we mark the conn as
    /// `Failed` so the task tears down right after.
    ///
    /// Standard error codes (RFC 9000 §20.1): `0x00 NO_ERROR`,
    /// `0x01 INTERNAL_ERROR`, `0x0a PROTOCOL_VIOLATION`, etc.
    /// `reason` is a UTF-8 byte slice; pass `b""` to omit.
    pub fn close_with_error(&mut self, error_code: u64, reason: &[u8]) {
        if self.close_pending.is_none() && !matches!(self.state, ConnState::Failed) {
            self.close_pending = Some((error_code, reason.to_vec()));
        }
    }

    /// Build the CONNECTION_CLOSE packet (if `close_pending` is set)
    /// without going through `flush_outbound`. The conn task uses
    /// this from its error-handling arm where it doesn't have a
    /// `TlsServerConfig` reference handy and where `process_datagram`
    /// has already returned, so the normal flush path won't run.
    /// No-op when no close is pending.
    pub fn flush_close(&mut self) {
        if let Some((error_code, reason)) = self.close_pending.take() {
            use executor::reactor::MAX_L2_HEADROOM;
            let mut datagram = self.take_datagram_buf(256);
            if self
                .encode_close_packet(datagram.vec_mut(), error_code, &reason)
                .is_ok()
                && datagram.len() > MAX_L2_HEADROOM
            {
                self.outbound.push_back(datagram);
                crate::diag::bump(&crate::diag::COUNTERS.connection_closes_emitted);
            }
            self.state = ConnState::Failed;
        }
    }

    /// Anti-amplification credit remaining (RFC 9000 §8.1.2). Pre-
    /// validation we may send at most 3× the bytes we've received.
    /// Returns u64::MAX once the path is validated. Used by
    /// `flush_outbound` and the per-encoder paths to suppress
    /// further emission when the credit would be exceeded.
    pub(super) fn anti_amp_remaining(&self) -> u64 {
        if self.path_validated {
            return u64::MAX;
        }
        let limit = self.bytes_received_pre_validation.saturating_mul(3);
        limit.saturating_sub(self.bytes_sent_pre_validation)
    }

    /// Account for `n` bytes leaving the conn. No-op once the path
    /// is validated. Called after each packet is appended to the
    /// outbound queue.
    pub(super) fn record_bytes_sent(&mut self, n: u64) {
        if !self.path_validated {
            self.bytes_sent_pre_validation = self.bytes_sent_pre_validation.saturating_add(n);
        }
    }

    /// Force a 1-RTT packet emission even if no inbound datagram
    /// just arrived — caller invokes this after writing data on a
    /// stream so the connection layer drains the send queue without
    /// waiting for the next inbound packet.
    pub fn flush(&mut self, config: &TlsServerConfig) -> Result<(), ConnError> {
        crate::diag::bump(&crate::diag::COUNTERS.flush_calls);
        self.flush_outbound(config)?;
        self.reap_finished_streams();
        Ok(())
    }

    // ── TLS state machine drive + outbound flush ────────────────

    pub(super) fn flush_outbound(&mut self, _config: &TlsServerConfig) -> Result<(), ConnError> {
        use executor::reactor::MAX_L2_HEADROOM;

        // CONNECTION_CLOSE short-circuits the normal flush flow.
        // RFC 9000 §10.2.1: once we decide to close, we send one
        // packet with the close frame and stop generating packets
        // in any space. Emit at the highest level we have send
        // keys for so the peer can decrypt it; clients that have
        // 1-RTT or Handshake keys will also have the keys for
        // every lower level.
        if let Some((error_code, reason)) = self.close_pending.take() {
            let mut datagram = self.take_datagram_buf(256);
            self.encode_close_packet(datagram.vec_mut(), error_code, &reason)?;
            if datagram.len() > MAX_L2_HEADROOM {
                self.outbound.push_back(datagram);
                crate::diag::bump(&crate::diag::COUNTERS.connection_closes_emitted);
            }
            self.state = ConnState::Failed;
            return Ok(());
        }

        // Build outbound packets in a single coalesced datagram.
        // Order matters: Initial first, then Handshake, then 1-RTT
        // (RFC 9000 §12.2). Each packet's tx-side CRYPTO bytes
        // come from QuicTls.pop_handshake at the matching level.
        let mut datagram = self.take_datagram_buf(1500);

        // Initial packet (if there are bytes to send or an ACK pending).
        // Skip if we've discarded our Initial keys per RFC 9001 §4.9.1
        // — `initial_send` is None and the matching `ack_pending`
        // state is conservatively cleared so it doesn't pile up.
        let mut initial_crypto = [0u8; 1024];
        let initial_n = self
            .tls
            .pop_handshake(CryptoLevel::Initial, &mut initial_crypto);
        if self.initial_keys_discarded {
            self.initial_space.ack_pending = false;
        } else if initial_n > 0 || self.initial_space.ack_pending {
            self.encode_initial_packet(
                datagram.vec_mut(),
                &initial_crypto[..initial_n],
                self.initial_space.ack_pending,
            )?;
            self.initial_space.ack_pending = false;
        }

        // Handshake packet (after Initial has at least an ACK).
        // Stack-allocate the drain buffer — the server flight is
        // bounded (cert + EE + CV + Finished, well under 8 KiB),
        // and the previous Vec::with_capacity(8192) was hitting
        // the heap on every flush.
        // Skip if we've discarded our Handshake keys per RFC 9001
        // §4.9.2 (peer sent a 1-RTT packet → both sides have moved
        // on); same shape as the Initial guard above. The pending
        // ACK state is dropped on the floor — peer doesn't expect
        // a Handshake-level ACK once they've started 1-RTT.
        let mut hs_crypto = [0u8; 8192];
        let hs_n = self
            .tls
            .pop_handshake(CryptoLevel::Handshake, &mut hs_crypto);
        if self.handshake_keys_discarded {
            self.handshake_space.ack_pending = false;
        } else if hs_n > 0 || self.handshake_space.ack_pending {
            self.encode_handshake_packet(
                datagram.vec_mut(),
                &hs_crypto[..hs_n],
                self.handshake_space.ack_pending,
            )?;
            self.handshake_space.ack_pending = false;
        }

        // 1-RTT packet — bundles ACK + HANDSHAKE_DONE + STREAM
        // frames + STREAM data drained from per-stream send queues.
        // Encode the FIRST 1-RTT packet inline with any
        // Initial/Handshake packets above to maximise coalescing.
        if matches!(self.state, ConnState::Established) {
            self.encode_one_rtt_packet(datagram.vec_mut())?;
        }
        if datagram.len() > MAX_L2_HEADROOM {
            // Anti-amplification gate (RFC 9000 §8.1.2). Pre-
            // validation we drop packets whose cumulative bytes
            // would exceed 3× what we've received from the peer.
            // Dropping rather than truncating is correct here:
            // the peer treats it as packet loss and retries, by
            // which time their address may be validated.
            // `n` is the *wire* size (excluding the L2/L3/L4
            // headroom prefix the reactor will consume).
            let n = (datagram.len() - MAX_L2_HEADROOM) as u64;
            if n <= self.anti_amp_remaining() {
                self.record_bytes_sent(n);
                self.outbound.push_back(datagram);
            } else {
                crate::diag::bump(&crate::diag::COUNTERS.anti_amp_throttled);
            }
        }

        // Drain remaining stream/CRYPTO data into ADDITIONAL 1-RTT
        // datagrams. Without this, a 6 KiB response would dribble
        // out at one ~1100-byte packet per inbound trigger event,
        // and on rapid-refresh load partial response bytes pile
        // up in `send_streams.outbound` faster than they can ship
        // — `fin_sent` never becomes true, the reaper can never
        // free the stream, and the heap grows.
        //
        // RFC 9000 §12.2 forbids coalescing two 1-RTT packets
        // into one UDP datagram (short-header has no length
        // field), so each extra packet becomes its own datagram.
        // Cap the loop at MAX_FLUSH_PACKETS so a wedged peer
        // can't make us spin emitting endlessly.
        if matches!(self.state, ConnState::Established) {
            const MAX_FLUSH_PACKETS: usize = 32;
            for _ in 0..MAX_FLUSH_PACKETS {
                if !self.has_pending_one_rtt_data() {
                    break;
                }
                // Same anti-amp gate for the multi-packet flush
                // tail. Dropping additional packets pre-validation
                // is fine — the peer will get the first packet
                // (which moves them to Handshake) and we'll send
                // the rest after validation.
                if self.anti_amp_remaining() == 0 {
                    break;
                }
                let mut more = self.take_datagram_buf(1500);
                self.encode_one_rtt_packet(more.vec_mut())?;
                if more.len() <= MAX_L2_HEADROOM {
                    break;
                }
                let n = (more.len() - MAX_L2_HEADROOM) as u64;
                if n > self.anti_amp_remaining() {
                    crate::diag::bump(&crate::diag::COUNTERS.anti_amp_throttled);
                    break;
                }
                self.record_bytes_sent(n);
                self.outbound.push_back(more);
            }
        }
        Ok(())
    }

    /// Whether any 1-RTT-level frame source has data ready to
    /// emit (besides the always-coalescable ACK / HANDSHAKE_DONE,
    /// which we already drain in the first pass). Used by
    /// `flush_outbound` to decide whether to emit another packet.
    fn has_pending_one_rtt_data(&self) -> bool {
        // Any send stream with bytes queued OR a close pending.
        for s in self.send_streams.values() {
            match s.state {
                crate::streams::SendState::FinSent => continue,
                crate::streams::SendState::Closing => return true,
                crate::streams::SendState::Open => {
                    if !s.outbound.is_empty() {
                        return true;
                    }
                }
            }
        }
        false
    }

    // ── Outbound encoding ───────────────────────────────────────

    /// Encode an Initial packet into `out`, appending to it. The
    /// Initial header carries our chosen SCID (`local_cid`) and
    /// the peer's CID as DCID. Payload = optional ACK + optional
    /// CRYPTO frame, with PADDING to a useful size.
    fn encode_initial_packet(
        &mut self,
        out: &mut Vec<u8>,
        crypto_bytes: &[u8],
        emit_ack: bool,
    ) -> Result<(), ConnError> {
        let send_keys = self
            .initial_send
            .as_ref()
            .ok_or(ConnError::BadState)?
            .clone();
        let pn = self.initial_space.next_send_pn;
        self.initial_space.next_send_pn += 1;

        // Build frames.
        let mut frames: Vec<u8> = Vec::with_capacity(1024);
        if emit_ack {
            self.append_ack_frame(&mut frames, &self.initial_space);
        }
        if !crypto_bytes.is_empty() {
            let mut tmp = vec![0u8; crypto_bytes.len() + 16];
            let n = write_crypto(0, crypto_bytes, &mut tmp).map_err(|_| ConnError::Wire)?;
            frames.extend_from_slice(&tmp[..n]);
        }

        // Reserve tail = TAG_LEN bytes for the AEAD tag at the end.
        let pn_length: usize = 4;
        let payload_len = frames.len();
        let length_field = (pn_length + payload_len + TAG_LEN) as u64;

        // First byte: 0xc0 | (pn_length-1).
        let first_byte: u8 = 0xc0 | ((pn_length as u8) - 1);
        let header_start = out.len();
        out.push(first_byte);
        out.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        // Initial-reply DCID is the client's SCID we recorded; for
        // the Initial response we MUST echo the client's chosen
        // SCID (= peer_cid) per RFC 9000 §7.2 (or the client_initial_dcid
        // until the client has picked one — for our case, peer_cid
        // is what the client sent as SCID on its first Initial).
        out.push(self.peer_cid.len() as u8);
        out.extend_from_slice(self.peer_cid.as_slice());
        out.push(self.local_cid.len() as u8);
        out.extend_from_slice(self.local_cid.as_slice());
        // Token Length VARINT = 0.
        out.push(0);
        // Length VARINT.
        let mut lf_buf = [0u8; 4];
        let n = write_varint(length_field, &mut lf_buf).map_err(|_| ConnError::Wire)?;
        out.extend_from_slice(&lf_buf[..n]);
        let pn_offset = out.len();
        // PN bytes (4-byte big-endian).
        out.extend_from_slice(&(pn as u32).to_be_bytes());
        let payload_offset = out.len();
        out.extend_from_slice(&frames);
        out.extend_from_slice(&[0u8; TAG_LEN]); // tag placeholder
        let total_end = out.len();

        let ack_eliciting = !crypto_bytes.is_empty();
        let byte_count = (total_end - header_start) as u32;
        self.seal_packet(
            out,
            header_start,
            pn_offset,
            payload_offset,
            payload_len,
            total_end,
            pn,
            &send_keys,
            true,
        )?;
        self.record_sent_packet(CryptoLevel::Initial, pn, ack_eliciting, byte_count);
        Ok(())
    }

    fn encode_handshake_packet(
        &mut self,
        out: &mut Vec<u8>,
        crypto_bytes: &[u8],
        emit_ack: bool,
    ) -> Result<(), ConnError> {
        let send_keys = self
            .handshake_send
            .as_ref()
            .ok_or(ConnError::BadState)?
            .clone();
        let pn = self.handshake_space.next_send_pn;
        self.handshake_space.next_send_pn += 1;

        let mut frames: Vec<u8> = Vec::with_capacity(crypto_bytes.len() + 64);
        if emit_ack {
            self.append_ack_frame(&mut frames, &self.handshake_space);
        }
        if !crypto_bytes.is_empty() {
            let mut tmp = vec![0u8; crypto_bytes.len() + 16];
            let n = write_crypto(0, crypto_bytes, &mut tmp).map_err(|_| ConnError::Wire)?;
            frames.extend_from_slice(&tmp[..n]);
        }

        let pn_length: usize = 4;
        let payload_len = frames.len();
        let length_field = (pn_length + payload_len + TAG_LEN) as u64;

        let first_byte: u8 = 0xe0 | ((pn_length as u8) - 1); // type=10 Handshake
        let header_start = out.len();
        out.push(first_byte);
        out.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        out.push(self.peer_cid.len() as u8);
        out.extend_from_slice(self.peer_cid.as_slice());
        out.push(self.local_cid.len() as u8);
        out.extend_from_slice(self.local_cid.as_slice());
        let mut lf_buf = [0u8; 4];
        let n = write_varint(length_field, &mut lf_buf).map_err(|_| ConnError::Wire)?;
        out.extend_from_slice(&lf_buf[..n]);
        let pn_offset = out.len();
        out.extend_from_slice(&(pn as u32).to_be_bytes());
        let payload_offset = out.len();
        out.extend_from_slice(&frames);
        out.extend_from_slice(&[0u8; TAG_LEN]);
        let total_end = out.len();

        let ack_eliciting = !crypto_bytes.is_empty();
        let byte_count = (total_end - header_start) as u32;
        self.seal_packet(
            out,
            header_start,
            pn_offset,
            payload_offset,
            payload_len,
            total_end,
            pn,
            &send_keys,
            true,
        )?;
        self.record_sent_packet(CryptoLevel::Handshake, pn, ack_eliciting, byte_count);
        Ok(())
    }

    /// Build a single 1-RTT packet that bundles the currently-due
    /// frames: ACK (if pending), HANDSHAKE_DONE (if not yet sent),
    /// MAX_STREAMS replenishment, post-handshake CRYPTO frames,
    /// and as many STREAM-frame chunks as fit before the per-packet
    /// budget.
    ///
    /// Writes every frame directly into `out` (the datagram Vec),
    /// no intermediate scratch Vec. The header is laid down first
    /// (short-header is fixed-size for our 8-byte DCID), frames
    /// follow, AEAD seals in place. Saves one full memcpy of the
    /// packet body per emitted packet vs. the old "build frames in
    /// scratch, then extend_from_slice into datagram" path.
    fn encode_one_rtt_packet(&mut self, out: &mut Vec<u8>) -> Result<(), ConnError> {
        // Per-packet body budget. Leaves headroom for short-header
        // (1+CID+pn=13) + tag (16) under MTU 1200; STREAM frame
        // headers add ~4-12 bytes of varint overhead.
        const PACKET_BODY_BUDGET: usize = 1100;

        let send_keys = match self.application_send.as_ref() {
            Some(k) => k.clone(),
            None => return Ok(()),
        };

        // ── Header ───────────────────────────────────────────────
        // Lay down the short-header bytes first so frames write
        // directly into the datagram payload region. We rollback
        // via `out.truncate(header_start)` if no frames are due.
        let pn_length: usize = 4;
        let header_start = out.len();
        let first_byte: u8 = FIXED_BIT | ((pn_length as u8) - 1);
        out.push(first_byte);
        out.extend_from_slice(self.peer_cid.as_slice());
        let pn_offset = out.len();
        // PN bytes — placeholder; we patch in the real pn after
        // we've decided to emit (so we don't burn a PN on rollback).
        out.extend_from_slice(&[0u8; 4]);
        let payload_offset = out.len();

        // Tracks whether the packet contains any non-ACK frame.
        // RFC 9002 §3: ack-eliciting iff carries a frame other than
        // ACK / PADDING / CONNECTION_CLOSE.
        let mut ack_eliciting = false;

        if self.application_space.ack_pending {
            self.append_ack_frame(out, &self.application_space);
            self.application_space.ack_pending = false;
        }
        if !self.handshake_done_sent {
            out.push(crate::frame::ftype::HANDSHAKE_DONE);
            self.handshake_done_sent = true;
            ack_eliciting = true;
        }

        // MAX_STREAMS replenishment (RFC 9000 §4.6 / §19.11).
        const STREAM_CREDIT_REFILL_AT: u64 = 256;
        const STREAM_CREDIT_WINDOW: u64 = 1024;
        if self.peer_max_streams_bidi_advertised
            <= self.peer_bidi_streams_opened + STREAM_CREDIT_REFILL_AT
        {
            self.peer_max_streams_bidi_advertised =
                self.peer_bidi_streams_opened + STREAM_CREDIT_WINDOW;
            append_max_streams_into(
                out,
                self.peer_max_streams_bidi_advertised,
                /* uni= */ false,
            )
            .map_err(|_| ConnError::Wire)?;
            ack_eliciting = true;
        }
        if self.peer_max_streams_uni_advertised
            <= self.peer_uni_streams_opened + STREAM_CREDIT_REFILL_AT
        {
            self.peer_max_streams_uni_advertised =
                self.peer_uni_streams_opened + STREAM_CREDIT_WINDOW;
            append_max_streams_into(
                out,
                self.peer_max_streams_uni_advertised,
                /* uni= */ true,
            )
            .map_err(|_| ConnError::Wire)?;
            ack_eliciting = true;
        }

        // Drain any 1-RTT-level handshake bytes (NewSessionTicket
        // emitted right after ClientFinished verifies; future
        // KeyUpdate / NewToken).
        let mut one_rtt_crypto = [0u8; 1024];
        let crypto_n = self
            .tls
            .pop_handshake(CryptoLevel::OneRtt, &mut one_rtt_crypto);
        if crypto_n > 0 {
            let offset = self.one_rtt_crypto_offset;
            let max_size = crypto_n + 16;
            let start = out.len();
            out.resize(start + max_size, 0);
            let n = write_crypto(offset, &one_rtt_crypto[..crypto_n], &mut out[start..])
                .map_err(|_| ConnError::Wire)?;
            out.truncate(start + n);
            self.one_rtt_crypto_offset += crypto_n as u64;
            ack_eliciting = true;
            crate::quic_event!(
                tickets_emitted,
                "size={} local_cid={}",
                crypto_n,
                crate::endpoint::hex8(self.local_cid.as_slice())
            );
        }

        // Drain pending STREAM data, directly into `out`. Use
        // iter_mut so we don't have to collect the stream IDs
        // into a temporary Vec just to satisfy the borrow
        // checker — the per-flush stream-ids alloc the old
        // shape required is gone.
        for (sid, s) in self.send_streams.iter_mut() {
            let body_so_far = out.len() - payload_offset;
            if body_so_far >= PACKET_BODY_BUDGET {
                break;
            }
            let max_chunk = PACKET_BODY_BUDGET.saturating_sub(body_so_far + 16);
            if max_chunk == 0 {
                break;
            }
            if s.pop_chunk_into(*sid, max_chunk, out)
                .map_err(|_| ConnError::Wire)?
            {
                ack_eliciting = true;
            }
        }

        let body_len = out.len() - payload_offset;
        if body_len == 0 {
            // No frames produced; rollback the header so the
            // caller's `out.is_empty()` check sees nothing.
            out.truncate(header_start);
            return Ok(());
        }

        // Commit the PN now that we know we're emitting.
        let pn = self.application_space.next_send_pn;
        self.application_space.next_send_pn += 1;
        out[pn_offset..pn_offset + 4].copy_from_slice(&(pn as u32).to_be_bytes());

        // Pad to ensure HP sample (4 bytes after PN start) has
        // 16 bytes of ciphertext after AEAD seal.
        while out.len() - pn_offset < 4 + HP_SAMPLE_LEN {
            out.push(0); // PADDING frame
        }
        let payload_len = out.len() - payload_offset;
        out.extend_from_slice(&[0u8; TAG_LEN]);
        let total_end = out.len();

        let byte_count = (total_end - header_start) as u32;
        self.seal_packet(
            out,
            header_start,
            pn_offset,
            payload_offset,
            payload_len,
            total_end,
            pn,
            &send_keys,
            false,
        )?;
        self.record_sent_packet(CryptoLevel::OneRtt, pn, ack_eliciting, byte_count);
        Ok(())
    }

    /// Build and seal a single packet carrying just a
    /// CONNECTION_CLOSE (transport) frame. Picks the highest level
    /// for which we have send keys: 1-RTT > Handshake > Initial.
    /// RFC 9000 §10.2.3 says a closing endpoint can emit the close
    /// in multiple packet number spaces if the peer might lack
    /// keys for the highest one — for now we keep it to one packet
    /// at the highest space, which works fine when the peer reaches
    /// at least the same level we have keys for (the common case).
    fn encode_close_packet(
        &mut self,
        out: &mut Vec<u8>,
        error_code: u64,
        reason: &[u8],
    ) -> Result<(), ConnError> {
        // Build the CONNECTION_CLOSE frame body. frame_type=0 means
        // "no specific frame triggered the close" — appropriate for
        // both internal errors and protocol violations not tied to
        // a single frame.
        let mut frame_buf = vec![0u8; reason.len() + 32];
        let frame_n = crate::frame::write_close_transport(
            error_code,
            /* frame_type */ 0,
            reason,
            &mut frame_buf,
        )
        .map_err(|_| ConnError::Wire)?;
        let frames = &frame_buf[..frame_n];

        if let Some(send_keys) = self.application_send.as_ref().cloned() {
            // 1-RTT short-header packet.
            let pn = self.application_space.next_send_pn;
            self.application_space.next_send_pn += 1;
            let pn_length: usize = 4;
            let header_start = out.len();
            let first_byte: u8 = FIXED_BIT | ((pn_length as u8) - 1);
            out.push(first_byte);
            out.extend_from_slice(self.peer_cid.as_slice());
            let pn_offset = out.len();
            out.extend_from_slice(&(pn as u32).to_be_bytes());
            let payload_offset = out.len();
            out.extend_from_slice(frames);
            // Pad so the HP sample (4 bytes after PN start) has 16
            // bytes of ciphertext after AEAD seal.
            while out.len() - pn_offset < 4 + HP_SAMPLE_LEN {
                out.push(0); // PADDING
            }
            let payload_len = out.len() - payload_offset;
            out.extend_from_slice(&[0u8; TAG_LEN]);
            let total_end = out.len();
            return self.seal_packet(
                out,
                header_start,
                pn_offset,
                payload_offset,
                payload_len,
                total_end,
                pn,
                &send_keys,
                false,
            );
        }

        if let Some(send_keys) = self.handshake_send.as_ref().cloned() {
            // Handshake long-header packet.
            let pn = self.handshake_space.next_send_pn;
            self.handshake_space.next_send_pn += 1;
            let pn_length: usize = 4;
            let payload_len = frames.len();
            let length_field = (pn_length + payload_len + TAG_LEN) as u64;
            let first_byte: u8 = 0xe0 | ((pn_length as u8) - 1);
            let header_start = out.len();
            out.push(first_byte);
            out.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
            out.push(self.peer_cid.len() as u8);
            out.extend_from_slice(self.peer_cid.as_slice());
            out.push(self.local_cid.len() as u8);
            out.extend_from_slice(self.local_cid.as_slice());
            let mut lf_buf = [0u8; 4];
            let n = write_varint(length_field, &mut lf_buf).map_err(|_| ConnError::Wire)?;
            out.extend_from_slice(&lf_buf[..n]);
            let pn_offset = out.len();
            out.extend_from_slice(&(pn as u32).to_be_bytes());
            let payload_offset = out.len();
            out.extend_from_slice(frames);
            out.extend_from_slice(&[0u8; TAG_LEN]);
            let total_end = out.len();
            return self.seal_packet(
                out,
                header_start,
                pn_offset,
                payload_offset,
                payload_len,
                total_end,
                pn,
                &send_keys,
                true,
            );
        }

        if let Some(send_keys) = self.initial_send.as_ref().cloned() {
            // Initial long-header packet.
            let pn = self.initial_space.next_send_pn;
            self.initial_space.next_send_pn += 1;
            let pn_length: usize = 4;
            let payload_len = frames.len();
            let length_field = (pn_length + payload_len + TAG_LEN) as u64;
            let first_byte: u8 = 0xc0 | ((pn_length as u8) - 1);
            let header_start = out.len();
            out.push(first_byte);
            out.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
            out.push(self.peer_cid.len() as u8);
            out.extend_from_slice(self.peer_cid.as_slice());
            out.push(self.local_cid.len() as u8);
            out.extend_from_slice(self.local_cid.as_slice());
            out.push(0); // Token Length VARINT = 0
            let mut lf_buf = [0u8; 4];
            let n = write_varint(length_field, &mut lf_buf).map_err(|_| ConnError::Wire)?;
            out.extend_from_slice(&lf_buf[..n]);
            let pn_offset = out.len();
            out.extend_from_slice(&(pn as u32).to_be_bytes());
            let payload_offset = out.len();
            out.extend_from_slice(frames);
            out.extend_from_slice(&[0u8; TAG_LEN]);
            let total_end = out.len();
            return self.seal_packet(
                out,
                header_start,
                pn_offset,
                payload_offset,
                payload_len,
                total_end,
                pn,
                &send_keys,
                true,
            );
        }

        // No send keys at any level — peer has no way to decrypt
        // a close packet. Caller falls through to silent close.
        Ok(())
    }

    /// Build and seal a single-byte PING probe at the requested
    /// level. Used by the PTO timer to force the peer to ACK so
    /// we can either (a) confirm the connection's still alive,
    /// or (b) advance loss detection by raising `largest_acked`
    /// past stale unacked PNs. The encoded packet is also recorded
    /// in `sent_packets` so it itself participates in the loss /
    /// RTT machinery.
    pub(super) fn encode_ping_probe(
        &mut self,
        out: &mut Vec<u8>,
        level: CryptoLevel,
    ) -> Result<(), ConnError> {
        let frames = [crate::frame::ftype::PING];

        match level {
            CryptoLevel::OneRtt => {
                let send_keys = match self.application_send.as_ref() {
                    Some(k) => k.clone(),
                    None => return Ok(()),
                };
                let pn = self.application_space.next_send_pn;
                self.application_space.next_send_pn += 1;
                let pn_length: usize = 4;
                let header_start = out.len();
                let first_byte: u8 = FIXED_BIT | ((pn_length as u8) - 1);
                out.push(first_byte);
                out.extend_from_slice(self.peer_cid.as_slice());
                let pn_offset = out.len();
                out.extend_from_slice(&(pn as u32).to_be_bytes());
                let payload_offset = out.len();
                out.extend_from_slice(&frames);
                while out.len() - pn_offset < 4 + HP_SAMPLE_LEN {
                    out.push(0);
                }
                let payload_len = out.len() - payload_offset;
                out.extend_from_slice(&[0u8; TAG_LEN]);
                let total_end = out.len();
                let byte_count = (total_end - header_start) as u32;
                self.seal_packet(
                    out,
                    header_start,
                    pn_offset,
                    payload_offset,
                    payload_len,
                    total_end,
                    pn,
                    &send_keys,
                    false,
                )?;
                self.record_sent_packet(CryptoLevel::OneRtt, pn, true, byte_count);
            }
            CryptoLevel::Handshake => {
                let send_keys = match self.handshake_send.as_ref() {
                    Some(k) => k.clone(),
                    None => return Ok(()),
                };
                let pn = self.handshake_space.next_send_pn;
                self.handshake_space.next_send_pn += 1;
                let pn_length: usize = 4;
                let payload_len = frames.len();
                let length_field = (pn_length + payload_len + TAG_LEN) as u64;
                let first_byte: u8 = 0xe0 | ((pn_length as u8) - 1);
                let header_start = out.len();
                out.push(first_byte);
                out.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
                out.push(self.peer_cid.len() as u8);
                out.extend_from_slice(self.peer_cid.as_slice());
                out.push(self.local_cid.len() as u8);
                out.extend_from_slice(self.local_cid.as_slice());
                let mut lf_buf = [0u8; 4];
                let n = write_varint(length_field, &mut lf_buf).map_err(|_| ConnError::Wire)?;
                out.extend_from_slice(&lf_buf[..n]);
                let pn_offset = out.len();
                out.extend_from_slice(&(pn as u32).to_be_bytes());
                let payload_offset = out.len();
                out.extend_from_slice(&frames);
                out.extend_from_slice(&[0u8; TAG_LEN]);
                let total_end = out.len();
                let byte_count = (total_end - header_start) as u32;
                self.seal_packet(
                    out,
                    header_start,
                    pn_offset,
                    payload_offset,
                    payload_len,
                    total_end,
                    pn,
                    &send_keys,
                    true,
                )?;
                self.record_sent_packet(CryptoLevel::Handshake, pn, true, byte_count);
            }
            CryptoLevel::Initial => {
                let send_keys = match self.initial_send.as_ref() {
                    Some(k) => k.clone(),
                    None => return Ok(()),
                };
                let pn = self.initial_space.next_send_pn;
                self.initial_space.next_send_pn += 1;
                let pn_length: usize = 4;
                let payload_len = frames.len();
                let length_field = (pn_length + payload_len + TAG_LEN) as u64;
                let first_byte: u8 = 0xc0 | ((pn_length as u8) - 1);
                let header_start = out.len();
                out.push(first_byte);
                out.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
                out.push(self.peer_cid.len() as u8);
                out.extend_from_slice(self.peer_cid.as_slice());
                out.push(self.local_cid.len() as u8);
                out.extend_from_slice(self.local_cid.as_slice());
                out.push(0); // Token Length VARINT = 0
                let mut lf_buf = [0u8; 4];
                let n = write_varint(length_field, &mut lf_buf).map_err(|_| ConnError::Wire)?;
                out.extend_from_slice(&lf_buf[..n]);
                let pn_offset = out.len();
                out.extend_from_slice(&(pn as u32).to_be_bytes());
                let payload_offset = out.len();
                out.extend_from_slice(&frames);
                out.extend_from_slice(&[0u8; TAG_LEN]);
                let total_end = out.len();
                let byte_count = (total_end - header_start) as u32;
                self.seal_packet(
                    out,
                    header_start,
                    pn_offset,
                    payload_offset,
                    payload_len,
                    total_end,
                    pn,
                    &send_keys,
                    true,
                )?;
                self.record_sent_packet(CryptoLevel::Initial, pn, true, byte_count);
            }
        }
        Ok(())
    }

    /// Common AEAD seal + HP protect. `out` is the assembled
    /// datagram; we operate on the slice from `header_start`
    /// to `total_end`.
    #[allow(clippy::too_many_arguments)]
    fn seal_packet(
        &self,
        out: &mut [u8],
        header_start: usize,
        pn_offset: usize,
        payload_offset: usize,
        payload_len: usize,
        total_end: usize,
        pn: u64,
        keys: &super::DirKeys,
        is_long: bool,
    ) -> Result<(), ConnError> {
        // Split `out` into the AAD prefix and the payload tail
        // without allocating. Previously this copied the AAD via
        // `to_vec()` because Rust won't let us hold both
        // `&out[..payload_offset]` and `&mut out[payload_offset..]`
        // from the same `&mut out`. `split_at_mut` carves the two
        // disjoint slices the borrow checker accepts.
        let nonce = packet_nonce(&keys.iv, pn);
        let (header_part, payload_part) = out.split_at_mut(payload_offset);
        let aad: &[u8] = &header_part[header_start..payload_offset];
        let payload_slice = &mut payload_part[..payload_len];
        let tag = keys.aead_seal(&nonce, aad, payload_slice);
        crate::diag::COUNTERS
            .aead_seal_bytes
            .fetch_add(payload_len as u64, core::sync::atomic::Ordering::Relaxed);
        crate::diag::COUNTERS
            .aead_seal_packets
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        out[payload_offset + payload_len..payload_offset + payload_len + TAG_LEN]
            .copy_from_slice(&tag);

        // Header protection sample.
        let sample_start = pn_offset + 4;
        if sample_start + HP_SAMPLE_LEN > total_end {
            return Err(ConnError::OutputTooSmall);
        }
        let mut sample = [0u8; HP_SAMPLE_LEN];
        sample.copy_from_slice(&out[sample_start..sample_start + HP_SAMPLE_LEN]);
        let mask = keys.hp_mask(&sample);

        let pn_length = 4usize;
        let (head, rest) = out.split_at_mut(pn_offset);
        apply_hp_mask(
            &mut head[header_start],
            &mut rest[..pn_length],
            &mask,
            is_long,
        );
        Ok(())
    }

    pub(super) fn append_ack_frame(&self, frames: &mut Vec<u8>, space: &SpaceState) {
        let largest = match space.largest_recv_pn {
            Some(x) => x,
            None => return,
        };
        let mut tmp = [0u8; 32];
        if let Ok(n) = write_ack(
            largest,
            /* delay */ 0,
            /* first_range */ 0,
            &[],
            &mut tmp,
        ) {
            frames.extend_from_slice(&tmp[..n]);
        }
    }
}
