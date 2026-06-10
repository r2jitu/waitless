// crates/proto/quic/src/conn/loss.rs — RFC 9002 loss detection + RTT
// estimation + PTO timer.
//
// `process_ack` is the inbound side: for each ACK, drop the
// acknowledged PNs from the matching space's `sent_packets` map,
// fold the largest newly-acked PN's send-time into the RTT EWMA,
// and run `detect_loss` to declare any packets stranded behind
// the packet- / time-threshold cutoffs lost. `record_sent_packet`
// is the outbound counterpart, called by `tx.rs`'s
// `encode_*_packet` helpers after each successful seal.
//
// `pto_period_us` / `pto_deadline_us` expose the PTO timer; the
// conn task in `endpoint.rs` races a sleep against the deadline
// and calls `send_pto_probe` when the sleep wins.

use net_cc::CongestionControl;

use super::{Connection, SentPacket, ack_remove_range};
use crate::tls::CryptoLevel;

impl Connection {
    /// PTO (Probe Timeout) period in microseconds, RFC 9002 §6.2.1:
    ///   `PTO = (SRTT + max(4 * RTTvar, kGranularity) + max_ack_delay) << pto_count`
    /// Until we have an SRTT sample, the base falls back to
    /// kInitialRtt = 333 ms. `pto_count` (the exponential backoff) grows
    /// each time a probe fires without progress and resets when an ACK
    /// acknowledges new data, so a deadlocked / unresponsive peer probes
    /// at a geometrically increasing interval instead of flooding PINGs.
    pub fn pto_period_us(&self) -> u64 {
        const K_INITIAL_RTT_US: u64 = 333_000;
        const K_GRANULARITY_US: u64 = 1_000;
        // The peer's advertised max_ack_delay (RFC 9000 §18.2), cached
        // when its transport params are applied; 25 ms default before.
        let max_ack_delay_us: u64 = self.peer_max_ack_delay_us;
        let base = match self.smoothed_rtt_us {
            None => K_INITIAL_RTT_US + K_GRANULARITY_US,
            Some(srtt) => srtt + (4 * self.rttvar_us).max(K_GRANULARITY_US) + max_ack_delay_us,
        };
        // Cap the exponent so the period can't overflow and a long-
        // unresponsive peer can't shift it to absurd values — the idle
        // timeout reaps such a conn long before count 10 (~1024× base).
        base.saturating_mul(1u64 << self.pto_count.min(10))
    }

    /// Microseconds-since-boot timestamp at which the PTO timer
    /// fires. `None` when we have no in-flight ack-eliciting packet
    /// (no probe needed). Picks the *earliest* deadline across all
    /// three spaces — a probe in any of them would advance the
    /// state machine.
    pub fn pto_deadline_us(&self) -> Option<u64> {
        let pto = self.pto_period_us();
        self.time_of_last_ack_eliciting_us
            .iter()
            .filter_map(|t| t.map(|x| x + pto))
            .min()
    }

    /// Send a PING-only probe at the level that has the oldest
    /// in-flight ack-eliciting packet. RFC 9002 §6.2.4 prefers
    /// retransmitting unacked CRYPTO/STREAM data here, but until
    /// frame retx is wired up, a PING is the next-best forcer of
    /// an ACK from the peer (which then either confirms previously
    /// sent packets via cumulative ACK, or signals their loss via
    /// silence). Returns `true` if a probe was actually emitted.
    pub fn send_pto_probe(&mut self) -> bool {
        // Find the level with the oldest unacked ack-eliciting send.
        // Initial / Handshake / Application = 0 / 1 / 2.
        let oldest = self
            .time_of_last_ack_eliciting_us
            .iter()
            .enumerate()
            .filter_map(|(i, t)| t.map(|x| (i, x)))
            .min_by_key(|(_, t)| *t);
        let level_idx = match oldest {
            Some((i, _)) => i,
            None => return false,
        };
        let level = match level_idx {
            0 => CryptoLevel::Initial,
            1 => CryptoLevel::Handshake,
            _ => CryptoLevel::OneRtt,
        };
        use nic_api::MAX_L2_HEADROOM;
        let mut datagram = self.take_datagram_buf(64);
        if self.encode_ping_probe(datagram.vec_mut(), level).is_ok()
            && datagram.len() > MAX_L2_HEADROOM
        {
            self.outbound.push_back(datagram);
            // Back off the next PTO (RFC 9002 §6.2.1). Reset in `process_ack`
            // when an ACK acknowledges new data.
            self.pto_count = self.pto_count.saturating_add(1);
            // Persistent congestion (RFC 9002 §7.6): once several
            // consecutive PTO periods have elapsed with no ACK, the path
            // is genuinely congested/down, not just bursty — collapse the
            // window to the minimum and restart slow start. We use the
            // PTO count as the trigger (rather than the §7.6.1 lost-time-
            // span test) because it CANNOT false-fire on transient burst
            // loss: `pto_count` only grows while the peer is silent and
            // resets to 0 on any newly-acked data. At the threshold the
            // peer has been quiet across ~PTO·(1+2)=3 PTO periods — the
            // ~3× span §7.6.1 looks for. Fire once at the crossing
            // (`==`), not on every later probe.
            const PERSISTENT_CONGESTION_PTO_THRESHOLD: u32 = 2;
            if self.pto_count == PERSISTENT_CONGESTION_PTO_THRESHOLD {
                self.cc.on_rto();
            }
            return true;
        }
        false
    }

    /// Walk the ACK ranges from an inbound ACK frame and:
    ///   1. drop matching entries from the matching space's
    ///      `sent_packets` map,
    ///   2. update `largest_acked`,
    ///   3. take an RTT sample from the largest newly-acked
    ///      ack-eliciting packet (RFC 9002 §5.1).
    ///
    /// `ack_delay` is the peer's reported delay before generating the
    /// ACK, as the RAW wire value — in `2^ack_delay_exponent` µs units
    /// (RFC 9000 §19.3.1). The RTT-sample site below scales it by the
    /// peer's advertised exponent and clamps it to the peer's
    /// `max_ack_delay` (RFC 9002 §5.3) before use.
    pub(super) fn process_ack(
        &mut self,
        level: CryptoLevel,
        largest_acknowledged: u64,
        ack_delay: u64,
        first_ack_range: u64,
        ack_ranges: crate::frame::AckRanges<'_>,
    ) {
        let space_idx = match level {
            CryptoLevel::Initial => 0usize,
            CryptoLevel::Handshake => 1,
            CryptoLevel::OneRtt => 2,
        };

        // Walk all ranges removing newly-acked PNs from sent_packets.
        // RFC 9000 §19.3.1: the first range covers
        // `[largest - first_ack_range, largest]`. Each subsequent
        // `(gap, length)` pair encodes one more range, with
        // `next_largest = prev_smallest - gap - 2` and
        // `next_smallest = next_largest - length`.
        //
        // We capture the SentPacket for `largest_acknowledged`
        // specifically, since RFC 9002 §5.1 requires the RTT
        // sample to come from THAT packet (only).
        let mut largest_pkt: Option<SentPacket> = None;
        // Sum of bytes-in-flight released by this ACK — fed to the
        // congestion controller's `on_ack` and subtracted from
        // `bytes_in_flight` below.
        let mut acked_bytes: u32 = 0;
        let space_now_empty: bool;
        {
            let space = match level {
                CryptoLevel::Initial => &mut self.initial_space,
                CryptoLevel::Handshake => &mut self.handshake_space,
                CryptoLevel::OneRtt => &mut self.application_space,
            };
            space.largest_acked = Some(match space.largest_acked {
                Some(x) => x.max(largest_acknowledged),
                None => largest_acknowledged,
            });
            let first_smallest = largest_acknowledged.saturating_sub(first_ack_range);
            ack_remove_range(
                space,
                first_smallest,
                largest_acknowledged,
                largest_acknowledged,
                &mut largest_pkt,
                &mut acked_bytes,
                &mut self.retx_frame_vec_pool,
            );
            let mut largest_smallest = first_smallest;
            for (gap, length) in ack_ranges {
                // gap=N means N PNs between prev_smallest and this
                // range's largest are NOT acked. So the next PN
                // covered is prev_smallest - gap - 2 down to that
                // minus length.
                let high = match largest_smallest.checked_sub(gap + 2) {
                    Some(v) => v,
                    None => break,
                };
                let low = high.saturating_sub(length);
                ack_remove_range(
                    space,
                    low,
                    high,
                    largest_acknowledged,
                    &mut largest_pkt,
                    &mut acked_bytes,
                    &mut self.retx_frame_vec_pool,
                );
                largest_smallest = low;
            }
            space_now_empty = space.sent_packets.is_empty();
        }

        // RTT sample (RFC 9002 §5.1). Only when the largest_acked
        // PN is newly acked AND its packet was ack-eliciting.
        if let Some(pkt) = largest_pkt
            && pkt.ack_eliciting
        {
            let now = crate::time::now_us();
            let latest = now.saturating_sub(pkt.time_sent_us);
            // Scale the raw wire value into µs by the peer's advertised
            // ack_delay_exponent (default 3 → 8 µs units; the old code
            // treated raw as µs, under-counting 8× even for default
            // peers), and clamp to the peer's max_ack_delay so an
            // inflated report can't deflate the RTT sample (RFC 9002
            // §5.3). Exponent ≤ 20 is parser-enforced, so the shift
            // can't overflow past the saturating multiply.
            let ack_delay_us = ack_delay
                .saturating_mul(1u64 << self.peer_ack_delay_exponent)
                .min(self.peer_max_ack_delay_us);
            self.update_rtt(latest, ack_delay_us);
        }
        // Release acked bytes from flight and grow the congestion
        // window (RFC 9002 §7.8 OnPacketAcked). After the RTT sample so
        // `on_ack` sees the fresh SRTT for its pacing-rate estimate.
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);
        if acked_bytes > 0 {
            // Progress: reset the PTO backoff exponent (RFC 9002 §6.2.1).
            self.pto_count = 0;
            let rtt = net_cc::Rtt::new(
                self.smoothed_rtt_us.unwrap_or(0) as u32,
                self.min_rtt_us.unwrap_or(0) as u32,
            );
            // ms timestamp for a time-based controller (CUBIC); NewReno ignores it.
            let now_ms = crate::time::now_us() / 1000;
            self.cc
                .on_ack(acked_bytes, self.bytes_in_flight, rtt, now_ms);
        }
        // Loss detection — runs after each ACK in the same space.
        // RFC 9002 §6.1: a sent packet is lost when it crosses the
        // packet threshold OR the time threshold; the decision logic
        // (and its arithmetic) lives in the shared `net_cc::loss` core.
        self.detect_loss(level);
        if space_now_empty {
            self.time_of_last_ack_eliciting_us[space_idx] = None;
        }
    }

    /// Walk one space's `sent_packets` after an ACK arrives and
    /// drop any that meet the RFC 9002 §6.1 packet- or time-threshold
    /// loss conditions. A lost packet's STREAM frames (staged on the
    /// `SentPacket` at send time) are re-queued into `retx_queue` for
    /// retransmission (RFC 9000 §13.3) at the end of this function;
    /// their bytes are released from flight and the congestion window
    /// is shrunk once per loss episode. A lost Initial/Handshake packet's
    /// CRYPTO fragments are likewise re-queued into `crypto_retx_queue`
    /// (RFC 9002 §6.2) and re-emitted at their original offset by
    /// `flush_outbound` — so handshake-packet loss is recovered by
    /// resending the bytes, not just by the PTO PING forcer in
    /// `send_pto_probe`. The per-PN counters give accurate "in flight"
    /// numbers and loss visibility.
    fn detect_loss(&mut self, level: CryptoLevel) {
        const K_GRANULARITY_US: u64 = 1_000;
        // Peer's max_ack_delay (RFC 9000 §18.2) — the value advertised in
        // its transport params, cached as `peer_max_ack_delay_us` (25 ms
        // RFC default until applied). Folded into the time threshold below —
        // but ONLY for the Application Data space (RFC 9002 §6.1.2): a
        // peer must not delay ACKs of Initial / Handshake packets, so
        // including it there would over-extend the threshold and delay
        // real handshake-loss recovery. This OneRtt-only rule is transport
        // policy, so it stays here; the threshold ARITHMETIC (packet
        // threshold K=3; time threshold 9/8·max(SRTT, latest_rtt) floored
        // at kGranularity, + max_ack_delay — incl. the §52 h3-real-RTT
        // spurious-collapse rationale) lives once in the shared core,
        // `net_cc::loss` (architecture-audit #4). QUIC passes µs ticks.
        let ack_delay_us = match level {
            CryptoLevel::OneRtt => self.peer_max_ack_delay_us,
            CryptoLevel::Initial | CryptoLevel::Handshake => 0,
        };
        let params = net_cc::loss::LossParams::rfc9002(
            self.smoothed_rtt_us.unwrap_or(0),
            self.latest_rtt_us.unwrap_or(0),
            K_GRANULARITY_US,
            ack_delay_us,
        );
        let now = crate::time::now_us();

        let space = match level {
            CryptoLevel::Initial => &mut self.initial_space,
            CryptoLevel::Handshake => &mut self.handshake_space,
            CryptoLevel::OneRtt => &mut self.application_space,
        };
        let largest_acked = match space.largest_acked {
            Some(x) => x,
            None => return,
        };

        // Lost-PN list. A Vec, not a fixed scratch array, so ALL packets
        // declared lost in a single ACK are recovered: a large
        // cumulative-ACK jump after a burst (the gve-storm case) can
        // declare hundreds lost at once, and any left unprocessed would
        // stay in `sent_packets` — pinning `bytes_in_flight` so the cwnd
        // gate never reopens, and never re-queuing their STREAM frames
        // until a later ACK / PTO — stalling the transfer exactly under
        // the heavy loss this path exists to handle. `Vec::new()` doesn't
        // allocate until the first push, so the common (no-loss) ACK —
        // the vast majority — stays alloc-free.
        let mut lost_buf: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
        let mut lost_threshold_n: usize = 0;
        let mut lost_time_n: usize = 0;
        // In-flight (unacked) sent-packet count at entry — sizes the
        // cascade for the `last_loss` diagnostic snapshot below.
        let inflight_pkts = space.sent_packets.len() as u64;
        // Walk in PN order; the shared core classifies each PN against
        // the thresholds. Threshold-lost PNs (lowest) naturally come
        // first; time-lost can appear after. Counters track how many of
        // each (for the diag); the list itself stays in PN order. The
        // returned loss-time deadline is dropped: QUIC re-runs detection
        // on the next ACK and the PTO probe covers a silent tail, so no
        // loss timer is armed (TCP RACK is the consumer that arms it).
        let _next_loss_deadline = params.detect(
            largest_acked,
            now,
            space.sent_packets.iter().map(|(pn, pkt)| (pn, pkt.time_sent_us)),
            |pn, by| {
                lost_buf.push(pn);
                match by {
                    net_cc::loss::LostBy::PacketThreshold => lost_threshold_n += 1,
                    net_cc::loss::LostBy::Time => lost_time_n += 1,
                }
            },
        );
        let total_lost = lost_threshold_n + lost_time_n;
        let mut lost_bytes: u32 = 0;
        // Lost STREAM frames, collected in PN order (lowest offset first)
        // and re-queued for retransmission after the `space` borrow ends.
        let mut lost_frames: alloc::vec::Vec<super::StreamRetx> = alloc::vec::Vec::new();
        // Lost CRYPTO fragments, re-queued (at their original offsets) for
        // retransmission after the `space` borrow ends (RFC 9002 §6.2).
        let mut lost_crypto: alloc::vec::Vec<super::CryptoRetx> = alloc::vec::Vec::new();
        // Age of the lowest-PN lost packet (lost_buf is filled in PN
        // order, so [0] is the smallest). Captured for `last_loss`:
        // an age well below one RTT means its ACK is still in flight =
        // a spurious threshold declaration.
        let mut min_lost_age_us: u64 = 0;
        for (i, &pn) in lost_buf.iter().enumerate() {
            if let Some(mut pkt) = space.sent_packets.remove(pn) {
                if i == 0 {
                    min_lost_age_us = now.saturating_sub(pkt.time_sent_us);
                }
                if pkt.in_flight {
                    lost_bytes = lost_bytes.saturating_add(pkt.byte_count);
                }
                lost_frames.append(&mut pkt.stream_frames);
                lost_crypto.append(&mut pkt.crypto_frames);
            }
        }
        let lost_threshold_n = lost_threshold_n as u64;
        let lost_time_n = lost_time_n as u64;
        if lost_threshold_n > 0 {
            crate::diag::COUNTERS
                .packets_lost_threshold
                .add(lost_threshold_n);
        }
        if lost_time_n > 0 {
            crate::diag::COUNTERS.packets_lost_time.add(lost_time_n);
        }
        if total_lost > 0 {
            crate::diag::LAST_LOSS.record(crate::diag::LossRecord {
                largest_acked,
                threshold_n: lost_threshold_n,
                time_n: lost_time_n,
                min_lost_pn: lost_buf[0],
                min_lost_age_us,
                inflight_pkts,
                at_us: now,
            });
        }
        // Release the lost packets' bytes from flight and shrink the
        // congestion window once per loss episode (RFC 9002 §7.8
        // OnPacketsLost; NewReno halves, guarded internally to one
        // reduction per recovery period). `space` is no longer borrowed.
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        if lost_bytes > 0 {
            self.cc.on_loss(lost_bytes, false);
        }
        // Re-queue the lost STREAM ranges for retransmission (RFC 9000
        // §13.3). `encode_one_rtt_packet` drains this before fresh data.
        // Count their bytes so the congestion gate treats in-flight +
        // awaiting-retransmit as one bound (else the queue grows unbounded).
        for f in &lost_frames {
            self.retx_bytes = self.retx_bytes.saturating_add(f.data.len() as u32);
        }
        self.retx_queue.extend(lost_frames);
        // Re-queue lost CRYPTO fragments. Unlike STREAM bytes these are
        // not congestion-controlled separately (the handshake flight is
        // tiny and bounded), so no `retx_bytes`-style accounting; the
        // flush re-emits them ahead of fresh handshake CRYPTO.
        if !lost_crypto.is_empty() {
            crate::diag::COUNTERS
                .crypto_frames_retransmitted
                .add(lost_crypto.len() as u64);
            self.crypto_retx_queue.extend(lost_crypto);
        }
    }

    /// RFC 9002 §5.3: SRTT/RTTvar EWMA update. Called once per
    /// inbound ACK that produced an RTT sample.
    fn update_rtt(&mut self, latest_rtt_us: u64, peer_ack_delay_us: u64) {
        self.latest_rtt_us = Some(latest_rtt_us);
        self.min_rtt_us = Some(match self.min_rtt_us {
            Some(x) => x.min(latest_rtt_us),
            None => latest_rtt_us,
        });
        // Adjusted RTT: subtract ack_delay if doing so doesn't
        // drop us below min_rtt. This compensates for processing
        // delay on the peer.
        let adjusted = if let Some(min) = self.min_rtt_us {
            if latest_rtt_us > min + peer_ack_delay_us {
                latest_rtt_us - peer_ack_delay_us
            } else {
                latest_rtt_us
            }
        } else {
            latest_rtt_us
        };

        match self.smoothed_rtt_us {
            None => {
                self.smoothed_rtt_us = Some(adjusted);
                self.rttvar_us = adjusted / 2;
            }
            Some(srtt) => {
                let rttvar_sample = srtt.abs_diff(adjusted);
                // RTTvar = 3/4 * RTTvar + 1/4 * sample
                self.rttvar_us = (3 * self.rttvar_us + rttvar_sample) / 4;
                // SRTT = 7/8 * SRTT + 1/8 * adjusted
                self.smoothed_rtt_us = Some((7 * srtt + adjusted) / 8);
            }
        }
    }

    /// Record a freshly-sealed packet in its space's `sent_packets`
    /// map and bump `time_of_last_ack_eliciting_us` if appropriate.
    /// Called from each `encode_*_packet` after `seal_packet`
    /// returns. RFC 9002 §A.4: this is `OnPacketSent`. The byte
    /// count is `total_end - header_start` (sealed wire bytes).
    pub(super) fn record_sent_packet(
        &mut self,
        level: CryptoLevel,
        pn: u64,
        ack_eliciting: bool,
        byte_count: u32,
    ) {
        let now = crate::time::now_us();
        // Take the STREAM frames the encoder staged for this packet (empty
        // for ACK-only / PING / CRYPTO packets) so they ride along for
        // retransmission on loss.
        let stream_frames = core::mem::take(&mut self.pending_sent_stream_frames);
        let crypto_frames = core::mem::take(&mut self.pending_sent_crypto_frames);
        let pkt = SentPacket {
            time_sent_us: now,
            ack_eliciting,
            in_flight: ack_eliciting,
            byte_count,
            stream_frames,
            crypto_frames,
        };
        let (space, idx) = match level {
            CryptoLevel::Initial => (&mut self.initial_space, 0usize),
            CryptoLevel::Handshake => (&mut self.handshake_space, 1usize),
            CryptoLevel::OneRtt => (&mut self.application_space, 2usize),
        };
        space.sent_packets.insert(pn, pkt);
        if ack_eliciting {
            self.time_of_last_ack_eliciting_us[idx] = Some(now);
            // RFC 9002 §7.8 OnPacketSent: ack-eliciting packets count
            // against bytes-in-flight. Released in `process_ack` (acked)
            // or `detect_loss` (lost).
            self.bytes_in_flight = self.bytes_in_flight.saturating_add(byte_count);
        }
    }

    /// Discard every sent packet in `level`'s space (Initial/Handshake
    /// key discard — RFC 9001 §4.9 / RFC 9002 §6.4): those packets no
    /// longer count toward bytes-in-flight. Use this instead of
    /// `sent_packets.clear()` so the congestion-control accounting stays
    /// accurate (a bare clear would strand their bytes in flight and
    /// permanently shrink the effective window).
    pub(super) fn discard_sent_packets(&mut self, level: CryptoLevel) {
        let space = match level {
            CryptoLevel::Initial => &mut self.initial_space,
            CryptoLevel::Handshake => &mut self.handshake_space,
            CryptoLevel::OneRtt => &mut self.application_space,
        };
        let freed: u32 = space
            .sent_packets
            .values()
            .filter(|p| p.in_flight)
            .map(|p| p.byte_count)
            .sum();
        space.sent_packets.clear();
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(freed);
    }
}
