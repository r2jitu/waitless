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

use super::{Connection, SentPacket, ack_remove_range};
use crate::tls::CryptoLevel;

impl Connection {
    /// PTO (Probe Timeout) period in microseconds, RFC 9002 §6.2.1:
    ///   `PTO = SRTT + max(4 * RTTvar, kGranularity) + max_ack_delay`
    /// Until we have an SRTT sample, falls back to kInitialRtt =
    /// 333 ms. We don't yet implement exponential backoff
    /// (`PTO * 2^pto_count`); a single missed probe is acceptable
    /// for first-pass behaviour.
    pub fn pto_period_us(&self) -> u64 {
        const K_INITIAL_RTT_US: u64 = 333_000;
        const K_GRANULARITY_US: u64 = 1_000;
        // Default peer max_ack_delay is 25 ms (RFC 9000 §18.2).
        let max_ack_delay_us: u64 = 25_000;
        match self.smoothed_rtt_us {
            None => K_INITIAL_RTT_US + K_GRANULARITY_US,
            Some(srtt) => srtt + (4 * self.rttvar_us).max(K_GRANULARITY_US) + max_ack_delay_us,
        }
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
        use executor::reactor::MAX_L2_HEADROOM;
        let mut datagram = self.take_datagram_buf(64);
        if self.encode_ping_probe(datagram.vec_mut(), level).is_ok()
            && datagram.len() > MAX_L2_HEADROOM
        {
            self.outbound.push_back(datagram);
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
    /// `ack_delay` is the peer's reported delay before generating
    /// the ACK, in microseconds (already scaled by their
    /// ack_delay_exponent on the wire — we treat the value as μs
    /// for the simple case where both ends use the default
    /// exponent of 3 → 8 μs units; close enough for now).
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
                ack_remove_range(space, low, high, largest_acknowledged, &mut largest_pkt);
                largest_smallest = low;
            }
            space_now_empty = space.sent_packets.is_empty();
        }

        // RTT sample (RFC 9002 §5.1). Only when the largest_acked
        // PN is newly acked AND its packet was ack-eliciting.
        if let Some(pkt) = largest_pkt
            && pkt.ack_eliciting
        {
            let now = tls::ticket::now_us();
            let latest = now.saturating_sub(pkt.time_sent_us);
            self.update_rtt(latest, ack_delay);
        }
        // Loss detection — runs after each ACK in the same space.
        // RFC 9002 §6.1: declare lost any sent packet that's both
        //   (a) lower than `largest_acked - kPacketThreshold` (3),
        //   AND
        //   (b) older than the time threshold
        //       `max(9/8 * max(SRTT, latest_rtt), kGranularity)`.
        // Either condition alone is sufficient on its own per the
        // RFC; we apply them as separate counters.
        self.detect_loss(level);
        if space_now_empty {
            self.time_of_last_ack_eliciting_us[space_idx] = None;
        }
    }

    /// Walk one space's `sent_packets` after an ACK arrives and
    /// drop any that meet the RFC 9002 §6.1 packet- or time-threshold
    /// loss conditions. We don't yet retransmit the frames that
    /// were in those packets — handshake- and stream-level retx
    /// is a follow-up that requires offset tracking through
    /// `pop_handshake` / `SendStream::pop_chunk`. For now, drop +
    /// counter is the contract: it gives accurate "in flight"
    /// numbers and visibility into loss without faking recovery.
    fn detect_loss(&mut self, level: CryptoLevel) {
        const K_PACKET_THRESHOLD: u64 = 3;
        const K_GRANULARITY_US: u64 = 1_000;
        // Cache `max_rtt` and `now` before borrowing through SpaceState.
        // Both `latest_rtt_us` and `smoothed_rtt_us` live on Connection.
        let max_rtt = self
            .smoothed_rtt_us
            .map(|s| s.max(self.latest_rtt_us.unwrap_or(0)))
            .unwrap_or(self.latest_rtt_us.unwrap_or(0));
        let time_threshold_us = ((max_rtt * 9) / 8).max(K_GRANULARITY_US);
        let now = tls::ticket::now_us();

        let space = match level {
            CryptoLevel::Initial => &mut self.initial_space,
            CryptoLevel::Handshake => &mut self.handshake_space,
            CryptoLevel::OneRtt => &mut self.application_space,
        };
        let largest_acked = match space.largest_acked {
            Some(x) => x,
            None => return,
        };

        // Stack-array scratch for the lost-PN list — typical case
        // is 0 lost; even under heavy loss, more than ~32 packets
        // declared lost in a single ACK is unusual. Avoiding the
        // Vec::new() allocations on the common (no loss) path
        // saves two allocs per ACK processed, and ACKs fire
        // multiple times per HTTP/3 response.
        const SCRATCH_CAP: usize = 64;
        let mut lost_buf: [u64; SCRATCH_CAP] = [0; SCRATCH_CAP];
        let mut lost_threshold_n: usize = 0;
        let mut lost_time_n: usize = 0;
        // Walk in PN order. Threshold-lost PNs come first
        // (lowest PNs). Time-lost can appear after them. We pack
        // both into the same buffer with threshold first;
        // counters track how many of each.
        for (&pn, pkt) in space.sent_packets.iter() {
            if pn >= largest_acked {
                break; // PN >= largest_acked are still in-flight
            }
            if pn + K_PACKET_THRESHOLD <= largest_acked {
                if lost_threshold_n + lost_time_n < SCRATCH_CAP {
                    lost_buf[lost_threshold_n + lost_time_n] = pn;
                    lost_threshold_n += 1;
                }
                continue;
            }
            if max_rtt > 0
                && now.saturating_sub(pkt.time_sent_us) > time_threshold_us
                && lost_threshold_n + lost_time_n < SCRATCH_CAP
            {
                lost_buf[lost_threshold_n + lost_time_n] = pn;
                lost_time_n += 1;
            }
        }
        let total_lost = lost_threshold_n + lost_time_n;
        for &pn in &lost_buf[..total_lost] {
            space.sent_packets.remove(&pn);
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
        let now = tls::ticket::now_us();
        let pkt = SentPacket {
            time_sent_us: now,
            ack_eliciting,
            in_flight: ack_eliciting,
            byte_count,
        };
        let (space, idx) = match level {
            CryptoLevel::Initial => (&mut self.initial_space, 0usize),
            CryptoLevel::Handshake => (&mut self.handshake_space, 1usize),
            CryptoLevel::OneRtt => (&mut self.application_space, 2usize),
        };
        space.sent_packets.insert(pn, pkt);
        if ack_eliciting {
            self.time_of_last_ack_eliciting_us[idx] = Some(now);
        }
    }
}
