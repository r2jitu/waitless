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

use super::{
    ConnError, ConnState, Connection, HS_CRYPTO_BUDGET, MAX_QUIC_DATAGRAM, SpaceState, StreamRetx,
    append_max_data_into, append_max_stream_data_into, append_max_streams_into,
};
use net_cc::CongestionControl;

use crate::crypto::{HP_SAMPLE_LEN, TAG_LEN, apply_hp_mask, packet_nonce};
use crate::frame::{write_ack, write_crypto};
use crate::tls::CryptoLevel;
use crate::wire::{FIXED_BIT, QUIC_VERSION_1, write_varint};
use alloc::vec;
use alloc::vec::Vec;
use tls::TlsServerConfig;

/// Per-packet 1-RTT payload budget. Leaves headroom for the short
/// header (1 + DCID + 4 pn) + AEAD tag under the path MTU; STREAM
/// frame headers add ~4-12 B of varint overhead. The UDP-GSO segment
/// size and the ≥2-packet GSO gate are both derived from this.
const PACKET_BODY_BUDGET: usize = 1100;

/// Floor on the spacing between paced sends, µs — a busy-spin guard so a
/// near-zero computed wait doesn't spin the conn task. The runtime timer is
/// µs-resolution (serviced once per event-loop iteration), so this is also
/// roughly the finest spacing we can reliably honor.
const MIN_PACE_INTERVAL_US: u64 = 10;

/// SRTT below which we treat the path as a datacenter-internal / policed link
/// and apply the fixed `LOW_RTT_PACE_RATE_BPS` cap instead of trusting
/// `cc.pacing_rate()`. Real-internet RTTs are ≫ 1 ms; the GCE internal VPC is
/// ~0.2 ms. At such a tiny SRTT `cc.pacing_rate()` (N·cwnd/srtt) is both
/// enormous AND unstable (coarse rate control → ramp/collapse thrash under
/// GCE's per-VM egress policer — measured: uncapped pacing collapsed to
/// ~0.3 req/s), so a fixed cap is what actually completes there.
const LOW_RTT_CAP_THRESHOLD_US: u64 = 1_000;

/// Fixed paced rate for the ultra-low-RTT / pre-sample regime, bytes/s
/// (100 Mbps). Conservative + stable; below GCE's per-VM egress policer so
/// downloads complete. Tunable up toward the policer ceiling once profiled.
const LOW_RTT_PACE_RATE_BPS: u64 = 12_500_000;

/// Burst-budget ceiling, in bytes. Deliberately BELOW one full data packet
/// (`MAX_QUIC_DATAGRAM / 2`): with the `budget > 0` gate this means a single
/// large data packet always drives the budget negative → exactly one large
/// packet per paced send (the GCE egress policer drops large packets bunched
/// in a burst — the HEADERS packet rides a ~1100 B data packet, so a multi-
/// packet burst loses it; a lone large packet passes, like the always-fine
/// single-packet /health). Small control / health-check packets (≪ this) stay
/// positive and ship back-to-back with no pacing delay — they're cheap to the
/// byte-based policer, and gating them on a full packet's worth of credit
/// added a ~1 ms timer wait to every small response (a 5× /health regression).
/// Throughput is set by the rate, not this. Tunable up once policer headroom
/// is known.
const MAX_PACE_BURST: i64 = MAX_QUIC_DATAGRAM as i64 / 2;

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
                crate::diag::COUNTERS.connection_closes_emitted.bump();
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
        crate::diag::COUNTERS.flush_calls.bump();
        self.flush_outbound(config)?;
        self.reap_finished_streams();
        Ok(())
    }

    // ── Egress pacing (RFC 9002 §7.7) ────────────────────────────
    //
    // The flush tail loop would dump the whole congestion window as one
    // back-to-back microburst. GCE's per-VM egress policer drops such an
    // unpaced burst (the multi-packet h3 download loss — see
    // reference_gce_h3_burst_loss; TCP dodges it via TSO, single-packet
    // /health never bursts). We pace at `cc.pacing_rate()` (N·cwnd/srtt) —
    // the RFC / Linux-`fq` rate, NO artificial cap — by arming the async
    // runtime's µs timer for each packet's departure (`pace_deadline_us`,
    // raced in the conn task's select). A token bucket bounds the burst:
    // `MAX_PACE_BURST` below one data packet → one large packet per paced
    // send. The only ceiling is `MIN_PACE_INTERVAL_US` (the timer's reliable
    // spacing floor), so on real-RTT paths this runs at line rate and only
    // the low-RTT bench is floored. This is the no-GSO fallback pacer.

    /// Paced egress rate in bytes/s. On a real-RTT path it's the RFC 9002 §7.7
    /// rate `cc.pacing_rate()` (N·cwnd/srtt) — NO artificial cap, so production
    /// runs at line rate (cc.pacing_rate converges to the path bandwidth, the
    /// async timer in `pace_deadline_us` smooths the transients, like Linux
    /// `fq`). On an ultra-low-RTT path (datacenter-internal / GCE VPC, SRTT <
    /// `LOW_RTT_CAP_THRESHOLD_US`) — or before the first RTT sample — that rate
    /// is enormous and unstable under GCE's per-VM egress policer, so fall back
    /// to the fixed `LOW_RTT_PACE_RATE_BPS` cap, which is stable and completes.
    /// Never returns 0.
    fn pace_rate(&self) -> u64 {
        match self.smoothed_rtt_us {
            // Real-RTT path: trust cc.pacing_rate (BDP-correct), uncapped.
            // `.max(1)` guards the `pace_deadline_us` division only.
            Some(srtt) if srtt >= LOW_RTT_CAP_THRESHOLD_US => self.cc.pacing_rate().max(1),
            // Ultra-low-RTT / pre-sample: a FIXED stable rate (cc.pacing_rate
            // thrashes here — see the const docs).
            _ => LOW_RTT_PACE_RATE_BPS,
        }
    }

    /// Refill the token bucket for the elapsed wall-clock and return whether
    /// a packet may be emitted now. Emits on any positive credit: a large
    /// data packet then drives the budget negative (next packet waits for
    /// `pace_deadline_us`), giving 1-large-packet bursts, while small packets
    /// keep the budget positive and ship without a pacing wait (see
    /// `MAX_PACE_BURST`).
    fn pace_gate(&mut self) -> bool {
        let now = tls::ticket::now_us();
        let rate = self.pace_rate(); // always > 0
        let elapsed = now.saturating_sub(self.pace_last_us);
        let add = rate.saturating_mul(elapsed) / 1_000_000;
        self.pace_budget = self
            .pace_budget
            .saturating_add(add as i64)
            .min(MAX_PACE_BURST);
        self.pace_last_us = now;
        self.pace_budget > 0
    }

    /// Debit the bucket by the wire bytes of a packet just emitted.
    fn pace_consume(&mut self, n: u64) {
        self.pace_budget = self.pace_budget.saturating_sub(n as i64);
    }

    /// Wall-clock μs at which the pacer next permits a send, or `None` when
    /// not pacing-limited (no pending 1-RTT data, or budget left). The conn
    /// task folds this into its timer race and re-flushes on wake. The wait is
    /// `bytes_owed / pacing_rate` (RFC 9002 §7.7) but never shorter than
    /// `MIN_PACE_INTERVAL_US`: at a huge low-RTT `cc.pacing_rate()` the
    /// computed wait is ~0, so the timer floor is what spaces the packets
    /// (and avoids a busy-spin on a 0 wait); at a real-RTT rate the computed
    /// wait dominates and we pace at line rate.
    pub fn pace_deadline_us(&self) -> Option<u64> {
        if !self.has_pending_one_rtt_data() || self.pace_budget > 0 {
            return None;
        }
        let rate = self.pace_rate(); // always > 0
        let deficit = (MAX_PACE_BURST - self.pace_budget) as u64;
        let wait = (deficit.saturating_mul(1_000_000) / rate).max(MIN_PACE_INTERVAL_US);
        Some(self.pace_last_us.saturating_add(wait))
    }

    // ── TLS state machine drive + outbound flush ────────────────

    pub(super) fn flush_outbound(&mut self, _config: &TlsServerConfig) -> Result<(), ConnError> {
        use executor::reactor::MAX_L2_HEADROOM;

        // Make sure the peer's send-side flow-control limits are applied
        // before the 1-RTT STREAM-data gate consults `peer_max_data`
        // (one-shot; no-op until the peer's transport params arrive).
        self.apply_peer_flow_control();

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
                crate::diag::COUNTERS.connection_closes_emitted.bump();
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

        // Handshake packet — first fragment, coalesced into this
        // datagram behind the Initial.
        //
        // The server flight (EncryptedExtensions + Certificate +
        // CertificateVerify + Finished) exceeds one packet for any
        // real leaf+intermediate cert chain. RFC 9001 §4.1.3: the
        // Handshake CRYPTO stream may span any number of packets.
        // We drain it `HS_CRYPTO_BUDGET` bytes at a time — this
        // first fragment here, the remainder as their own
        // datagrams in the handshake-tail loop below — so no
        // datagram exceeds `MAX_QUIC_DATAGRAM`. A small fixed-size
        // drain buffer makes an oversized handshake packet
        // structurally unrepresentable: you cannot pop more bytes
        // than the array holds. (A single oversized datagram is
        // both a path-MTU violation AND, on the zero-copy `TxSlot`
        // send path, a `Vec` realloc off driver-owned memory =>
        // heap corruption — the gve h3 crash this fixes.)
        //
        // Skip entirely once Handshake keys are discarded (RFC 9001
        // §4.9.2); the pending ACK is dropped — the peer has moved
        // to 1-RTT and won't expect a Handshake-level ACK.
        if self.handshake_keys_discarded {
            self.handshake_space.ack_pending = false;
        } else {
            let mut hs_crypto = [0u8; HS_CRYPTO_BUDGET];
            let hs_n = self
                .tls
                .pop_handshake(CryptoLevel::Handshake, &mut hs_crypto);
            if hs_n > 0 || self.handshake_space.ack_pending {
                self.encode_handshake_packet(
                    datagram.vec_mut(),
                    &hs_crypto[..hs_n],
                    self.handshake_space.ack_pending,
                )?;
                self.handshake_space.ack_pending = false;
            }
        }

        // 1-RTT packet — bundles ACK + HANDSHAKE_DONE + STREAM
        // frames + STREAM data drained from per-stream send queues.
        // Encode the FIRST 1-RTT packet inline with any Initial /
        // Handshake packets above to maximise coalescing. 1-RTT is
        // only reached once Established — strictly after the whole
        // Handshake flight has been sent — so it never shares a
        // datagram with the large multi-fragment flight.
        if matches!(self.state, ConnState::Established) {
            // Pace the first 1-RTT packet too, not just the tail loop. The
            // conn task batches many inbound datagrams and flushes after
            // each, then ships all queued packets together; an unmetered
            // first packet per flush lets a batch emit one burst per inbound
            // datagram, defeating the pacer (the GCE microburst returns —
            // observed as a 7-packet back-to-back cluster). Gate it on the
            // token bucket — but ONLY when it would carry congestion-
            // controlled STREAM data: an ACK-/control-only packet must never
            // be paced (small, harmless to the policer, and pacing it could
            // strand an ACK since `pace_deadline_us` only re-arms while
            // stream data is pending). Debit the 1-RTT wire bytes either way.
            let pace_ok = !self.has_pending_one_rtt_data() || self.pace_gate();
            if pace_ok {
                let before = datagram.len();
                self.encode_one_rtt_packet(datagram.vec_mut())?;
                self.pace_consume((datagram.len() - before) as u64);
            }
        }
        // Invariant: every datagram stays within MAX_QUIC_DATAGRAM
        // (see the const's docs — protocol MTU *and* TX-slot
        // capacity). Caught here in debug builds; on the `TxSlot`
        // send path an overrun also trips the always-on guard in
        // `DatagramBuf::into_tx_handle`.
        debug_assert!(
            datagram.len() <= MAX_QUIC_DATAGRAM,
            "QUIC datagram {} B exceeds MAX_QUIC_DATAGRAM {} B",
            datagram.len(),
            MAX_QUIC_DATAGRAM,
        );
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
                crate::diag::COUNTERS.anti_amp_throttled.bump();
            }
        }

        // Handshake CRYPTO that did not fit the first fragment →
        // additional Handshake packets, each its own datagram.
        // This is what keeps the server flight within the path MTU
        // for a real (leaf + intermediate) cert chain. Mirrors the
        // 1-RTT multi-packet tail below; RFC 9000 §12.2 permits
        // coalescing Handshake packets, but one packet per datagram
        // is simplest and keeps every datagram comfortably small.
        if !self.handshake_keys_discarded {
            const MAX_HS_PACKETS: usize = 16;
            for _ in 0..MAX_HS_PACKETS {
                if !self.tls.has_pending_handshake() {
                    break;
                }
                // Same anti-amplification gate as the first
                // datagram (RFC 9000 §8.1.2).
                if self.anti_amp_remaining() == 0 {
                    break;
                }
                let mut hs_crypto = [0u8; HS_CRYPTO_BUDGET];
                let hs_n = self
                    .tls
                    .pop_handshake(CryptoLevel::Handshake, &mut hs_crypto);
                if hs_n == 0 {
                    break;
                }
                let mut more = self.take_datagram_buf(1500);
                self.encode_handshake_packet(more.vec_mut(), &hs_crypto[..hs_n], false)?;
                debug_assert!(
                    more.len() <= MAX_QUIC_DATAGRAM,
                    "QUIC Handshake datagram {} B exceeds MAX_QUIC_DATAGRAM {} B",
                    more.len(),
                    MAX_QUIC_DATAGRAM,
                );
                if more.len() <= MAX_L2_HEADROOM {
                    break;
                }
                let n = (more.len() - MAX_L2_HEADROOM) as u64;
                if n > self.anti_amp_remaining() {
                    crate::diag::COUNTERS.anti_amp_throttled.bump();
                    break;
                }
                self.record_bytes_sent(n);
                self.outbound.push_back(more);
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
        // Bulk tail: prefer ONE UDP-GSO super-packet (zero-copy + a
        // single descriptor; the device segments + paces). `try_flush_gso`
        // returns false when there's no hardware GSO, too little data, or
        // the window is blocked — then fall through to the per-datagram
        // tail loop below (which keeps the egress pacer for the no-GSO
        // microburst).
        if matches!(self.state, ConnState::Established) && self.try_flush_gso()? {
            return Ok(());
        }
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
                // Pacing gate (RFC 9002 §7.7): stop the tail burst once the
                // token bucket is spent; the conn task re-flushes at
                // `pace_deadline_us()`. Bounds the per-flush microburst the
                // GCE egress policer would otherwise drop. The first 1-RTT
                // packet above is unmetered, so HEADERS / a small response
                // still ship immediately and every flush makes ≥1 pkt of
                // progress (no pacer-induced deadlock).
                if !self.pace_gate() {
                    break;
                }
                let mut more = self.take_datagram_buf(1500);
                self.encode_one_rtt_packet(more.vec_mut())?;
                if more.len() <= MAX_L2_HEADROOM {
                    break;
                }
                let n = (more.len() - MAX_L2_HEADROOM) as u64;
                if n > self.anti_amp_remaining() {
                    crate::diag::COUNTERS.anti_amp_throttled.bump();
                    break;
                }
                self.pace_consume(n);
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
        // Retransmissions waiting to go out (RFC 9000 §13.3).
        if !self.retx_queue.is_empty() {
            return true;
        }
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

    /// Sum of 1-RTT stream bytes queued to send — fresh outbound across
    /// open send streams plus the retransmit backlog. Gates UDP-GSO: we
    /// only coalesce into a super-packet when there's ≥2 packets' worth,
    /// so a small single-packet response (a 60-byte /health) stays on the
    /// per-datagram path instead of being padded to a full GSO segment.
    fn pending_one_rtt_stream_bytes(&self) -> usize {
        let mut n = self.retx_bytes as usize;
        for s in self.send_streams.values() {
            n = n.saturating_add(s.buffered_len());
        }
        n
    }

    /// Per-connection UDP-GSO segment size = the largest 1-RTT packet
    /// this connection emits: short header (1 + DCID + 4 pn) + the
    /// payload budget + AEAD tag. Every GSO segment is padded to exactly
    /// this so the device can split the super-buffer at fixed offsets.
    fn gso_segment_size(&self) -> usize {
        1 + self.peer_cid.len() + 4 + PACKET_BODY_BUDGET + TAG_LEN
    }

    /// Emit the bulk 1-RTT tail as one UDP-GSO super-packet when the
    /// driver has hardware UDP segmentation: seal up to `MAX_GSO_SEGMENTS`
    /// back-to-back QUIC packets (each padded to `gso_segment_size`) into
    /// one big-pool slot and push it as a `GsoSlot` — `ship_datagram`
    /// hands the driver a single segmentation descriptor and the device
    /// splits it into N UDP datagrams on the wire. This replaces the
    /// per-datagram tail loop's N descriptors + N doorbells with one, and
    /// removes the unpaced microburst the per-packet pacer was guarding
    /// against (the cwnd is the limiter; the NIC paces the segmented
    /// output). Returns `Ok(true)` if a super-packet was produced (caller
    /// skips the per-packet tail), `Ok(false)` to fall through to the
    /// per-datagram path (no HW GSO, too little data, or window-blocked).
    fn try_flush_gso(&mut self) -> Result<bool, ConnError> {
        if !matches!(self.state, ConnState::Established) {
            return Ok(false);
        }
        let gso = self.gso_segment_size();
        let window = self.cc.window() as usize;
        let in_flight = self.bytes_in_flight as usize;
        // Need ≥2 packets of cwnd budget AND ≥2 packets of pending stream
        // data, else GSO under-fills or wastes padding.
        if window.saturating_sub(in_flight) < 2 * gso
            || self.pending_one_rtt_stream_bytes() < 2 * PACKET_BODY_BUDGET
        {
            return Ok(false);
        }
        let mut buf = match self.take_gso_datagram_buf(gso as u16) {
            Some(b) => b,
            None => return Ok(false), // big pool full / no HW GSO
        };
        let cap = buf.vec().capacity();
        const MAX_GSO_SEGMENTS: usize = 16;
        let mut n = 0usize;
        while n < MAX_GSO_SEGMENTS {
            if !self.has_pending_one_rtt_data() {
                break;
            }
            if buf.len() + gso > cap {
                break; // no room for another full segment in the slot
            }
            if (self.bytes_in_flight as usize) + gso > window {
                break; // cwnd-blocked
            }
            let before = buf.len();
            self.encode_one_rtt_packet_padded(buf.vec_mut(), Some(gso))?;
            let produced = buf.len() - before;
            if produced == 0 {
                break; // nothing emittable (control-only / fc-blocked)
            }
            self.record_bytes_sent(produced as u64);
            n += 1;
        }
        if n == 0 {
            // Nothing encoded → no state mutated; drop the slot (its
            // handle's Drop returns it) and let the per-packet path run.
            return Ok(false);
        }
        self.outbound.push_back(buf);
        Ok(true)
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
            // The server flight is fragmented across Handshake
            // packets (see `flush_outbound`), so each CRYPTO frame
            // carries this fragment's offset in the Handshake
            // CRYPTO stream — the peer reassembles by offset
            // (RFC 9001 §4.1.3). `+ 24` covers the CRYPTO frame
            // header (type byte + offset varint + length varint)
            // for any offset/length we emit.
            let mut tmp = vec![0u8; crypto_bytes.len() + 24];
            let n = write_crypto(self.handshake_crypto_offset, crypto_bytes, &mut tmp)
                .map_err(|_| ConnError::Wire)?;
            frames.extend_from_slice(&tmp[..n]);
            self.handshake_crypto_offset += crypto_bytes.len() as u64;
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
        self.encode_one_rtt_packet_padded(out, None)
    }

    /// As [`Self::encode_one_rtt_packet`], but when `pad_to_wire` is
    /// `Some(g)` the packet's payload is topped up with PADDING frames
    /// (0x00, AEAD-protected, ignored by the peer) so the sealed packet
    /// is exactly `g` wire bytes. Hardware UDP GSO requires every
    /// segment but the last to be an identical `gso_size` — the GSO
    /// flush pads each packet so the device can split the super-buffer.
    fn encode_one_rtt_packet_padded(
        &mut self,
        out: &mut Vec<u8>,
        pad_to_wire: Option<usize>,
    ) -> Result<(), ConnError> {
        // `PACKET_BODY_BUDGET` is the module-level const (shared with the
        // UDP-GSO segment-size math).
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

        // ── Flow-control credit (RFC 9000 §4.1) ──────────────────
        //
        // Slide the receive windows forward as the app drains data so
        // an upload can run past the initial transport-param limits.
        // Pull model: we re-check the condition every time we build a
        // 1-RTT packet, so credit naturally piggybacks on the ACKs we
        // send for inbound STREAM frames (and on the proactive flush
        // `endpoint::recv` does after consuming). Refill when less than
        // half a window of credit remains — keeps ≥ half a window open
        // without a MAX_* frame per packet.
        //
        // MAX_DATA: conn-level ceiling above all per-stream limits.
        const MAX_DATA_WINDOW: u64 = 1 << 20; // 1 MiB, matches initial_max_data
        let max_data_threshold =
            self.max_data_advertised.saturating_sub(self.data_consumed) <= MAX_DATA_WINDOW / 2;
        // Emit on the half-window threshold, or when the peer signalled
        // DATA_BLOCKED (re-advertise the current ceiling to recover a
        // lost MAX_DATA). Only slide the ceiling on the threshold path.
        if max_data_threshold || self.force_max_data {
            if max_data_threshold {
                // Clamp to the QUIC max varint (2^62-1) so a runaway
                // ceiling can't make `write_varint` fail and tear the
                // conn down — unreachable in practice (4.6 EB/conn).
                self.max_data_advertised =
                    (self.data_consumed + MAX_DATA_WINDOW).min((1u64 << 62) - 1);
            }
            append_max_data_into(out, self.max_data_advertised).map_err(|_| ConnError::Wire)?;
            self.force_max_data = false;
            ack_eliciting = true;
        }

        // MAX_STREAM_DATA: per receive stream. Skip fully-closed
        // streams (the peer won't send more) and stop once the packet
        // is near full — any stream that misses out this round gets its
        // credit on the next flush.
        const STREAM_DATA_WINDOW: u64 = crate::streams::INITIAL_MAX_STREAM_DATA; // 256 KiB
        // STREAM_DATA_BLOCKED doesn't name the stream in our skip path,
        // so re-advertise every open recv stream — re-sending an
        // unchanged MAX_STREAM_DATA is idempotent.
        let force_stream = self.force_max_stream_data;
        let mut stream_sweep_complete = true;
        for (sid, rs) in self.recv_streams.iter_mut() {
            if out.len() - header_start > PACKET_BODY_BUDGET {
                stream_sweep_complete = false;
                break;
            }
            if rs.is_closed() {
                continue;
            }
            let consumed = rs.consumed();
            let threshold = rs.recv_max.saturating_sub(consumed) <= STREAM_DATA_WINDOW / 2;
            if threshold || force_stream {
                if threshold {
                    rs.recv_max = (consumed + STREAM_DATA_WINDOW).min((1u64 << 62) - 1);
                }
                append_max_stream_data_into(out, *sid, rs.recv_max)
                    .map_err(|_| ConnError::Wire)?;
                ack_eliciting = true;
            }
        }
        // Cleared only once every open stream was re-advertised; if the
        // packet budget cut the sweep short, leave it set so the rest
        // re-advertise next packet. (If the peer is still stuck after a
        // full sweep it re-sends *_BLOCKED, which re-sets the flag.)
        if stream_sweep_complete {
            self.force_max_stream_data = false;
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

        // Drain STREAM data into `out` — retransmissions first, then
        // fresh data. Frames emitted here are recorded in `pkt_frames`
        // and handed to `record_sent_packet` (via
        // `pending_sent_stream_frames`) so they can be retransmitted if
        // this packet is lost.
        //
        // ── Congestion gate (RFC 9002 §7) ────────────────────────────
        // Both retransmitted AND fresh STREAM data are congestion-controlled
        // and must fit under the window. `window()` is the cwnd;
        // `bytes_in_flight` is what's already on the wire. `wire_budget` is
        // the room left under cwnd — the retx drain and the fresh loop both
        // spend from it. When it's exhausted the packet carries only
        // ACK / control frames (not congestion-controlled), leaving unsent
        // data queued to backpressure the handler via `stream_drain_below`.
        //
        // Gating RETRANSMISSIONS here (not just on packet room) is what stops
        // the gve-path retransmit storm: slow-start grows cwnd to the 2 MiB
        // cap across a keep-alive conn, so a full response burst overruns the
        // path; the cumulative ACK jumps, `detect_loss` threshold-declares
        // the whole un-ACKed backlog, and an UNGATED retx drain re-sends it
        // cwnd-unbounded (MAX_FLUSH_PACKETS/flush). The client can only ACK
        // the highest, so the rest are re-declared every round → ~60× over-
        // send, never converging. Pacing retx to cwnd lets recovery settle
        // at what the path actually sustains. Computed before the `iter_mut`
        // borrow so `self.cc` isn't aliased.
        let window = self.cc.window() as usize;
        let in_flight = self.bytes_in_flight as usize;
        let mut wire_budget = window.saturating_sub(in_flight);
        let mut pkt_frames: alloc::vec::Vec<StreamRetx> = alloc::vec::Vec::new();

        // (a) Retransmissions (RFC 9000 §13.3): re-send lost ranges before
        // any fresh data so the receiver's gap fills promptly. Gated on
        // packet room AND `wire_budget`. A retx moves its bytes from the
        // queue back onto the wire (retx_bytes↓ now, in-flight↑ when the
        // packet is recorded), so it spends `wire_budget`. A retx chunk is
        // ≤ one packet's payload and the minimum cwnd is 2·MSS, so a chunk
        // always fits on an empty wire — recovery can't deadlock. Each
        // queued range is ≤ one packet's payload; if it doesn't fit this
        // (partly-full) packet, leave it for the next packet in the flush.
        while let Some(front) = self.retx_queue.front() {
            let body_so_far = out.len() - payload_offset;
            let room = PACKET_BODY_BUDGET.saturating_sub(body_so_far + 16);
            if room == 0 || front.data.len() > room {
                break;
            }
            // cwnd gate — but always allow one packet onto an empty wire so
            // a collapsed cwnd still makes forward progress.
            if front.data.len() > wire_budget && !(in_flight == 0 && pkt_frames.is_empty()) {
                break;
            }
            let rtx = self.retx_queue.pop_front().unwrap();
            self.retx_bytes = self.retx_bytes.saturating_sub(rtx.data.len() as u32);
            wire_budget = wire_budget.saturating_sub(rtx.data.len());
            crate::frame::append_stream_header(rtx.sid, rtx.offset, rtx.fin, rtx.data.len(), out)
                .map_err(|_| ConnError::Wire)?;
            out.extend_from_slice(&rtx.data);
            ack_eliciting = true;
            pkt_frames.push(rtx);
        }

        // Fresh-data budget: the remaining wire room, additionally held
        // behind any retransmit backlog — don't grow the in-flight set while
        // lost data still awaits resend, which also bounds total retained
        // send memory under heavy loss. `retx_bytes` is what's still queued.
        let mut cc_budget =
            wire_budget.min(window.saturating_sub(in_flight + self.retx_bytes as usize));

        // (b) Fresh STREAM data, gated by cwnd + send-side flow control
        // (RFC 9000 §4.1: conn-level MAX_DATA + per-stream MAX_STREAM_DATA).
        let mut conn_fc_budget = self.peer_max_data.saturating_sub(self.data_sent) as usize;
        let mut data_sent_delta: u64 = 0;
        for (sid, s) in self.send_streams.iter_mut() {
            // cwnd / conn-level FC are global — once exhausted no stream
            // can send this packet.
            if cc_budget == 0 || conn_fc_budget == 0 {
                break;
            }
            let body_so_far = out.len() - payload_offset;
            if body_so_far >= PACKET_BODY_BUDGET {
                break;
            }
            // Per-stream send FC: bytes still authorized on this stream.
            let stream_fc_budget = s.peer_max_stream_data.saturating_sub(s.send_offset) as usize;
            let max_chunk = PACKET_BODY_BUDGET
                .saturating_sub(body_so_far + 16)
                .min(cc_budget)
                .min(conn_fc_budget)
                .min(stream_fc_budget);
            if max_chunk == 0 {
                // This stream is flow-control- (or packet-) blocked; its
                // data stays queued (backpressuring the handler). Other
                // streams may still have credit, so try the next.
                continue;
            }
            // `pop_chunk` returns the owned bytes (the copy retained for
            // retransmission); we frame them into `out` ourselves.
            if let Some((offset, data, fin)) = s.pop_chunk(max_chunk) {
                crate::frame::append_stream_header(*sid, offset, fin, data.len(), out)
                    .map_err(|_| ConnError::Wire)?;
                out.extend_from_slice(&data);
                ack_eliciting = true;
                let data_popped = data.len();
                cc_budget = cc_budget.saturating_sub(data_popped);
                conn_fc_budget = conn_fc_budget.saturating_sub(data_popped);
                data_sent_delta += data_popped as u64;
                pkt_frames.push(StreamRetx {
                    sid: *sid,
                    offset,
                    fin,
                    data,
                });
            }
        }
        self.data_sent = self.data_sent.saturating_add(data_sent_delta);
        // Stage the frames this packet carried so `record_sent_packet`
        // can retain them for retransmission.
        if !pkt_frames.is_empty() {
            self.pending_sent_stream_frames = pkt_frames;
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
        // UDP-GSO equal-segment padding: top the payload up with PADDING
        // frames (0x00) so the sealed packet (header + payload + tag) is
        // exactly `g` bytes. Only the GSO flush sets this; the per-packet
        // path passes None and never pads beyond the HP-sample minimum.
        if let Some(g) = pad_to_wire {
            while (out.len() - header_start) + TAG_LEN < g {
                out.push(0); // PADDING frame
            }
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
        crate::diag::COUNTERS.aead_seal_bytes.add(payload_len as u64);
        crate::diag::COUNTERS.aead_seal_packets.bump();
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
