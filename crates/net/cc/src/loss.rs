// net/cc/src/loss.rs — shared loss-detection decision core (architecture-
// audit direction #4: build TCP's RACK as the shared core from day one;
// QUIC's RFC 9002 detector is ported here and QUIC re-homed onto it, TCP
// RACK consumes it next).
//
// QUIC's RFC 9002 §6.1 loss detection and TCP's RACK-TLP (RFC 8985) are
// the same algorithm: a sent unit is lost when it trails the highest
// acknowledged unit by a reordering distance (the PACKET threshold) or has
// outlived an RTT-derived reordering window (the TIME threshold). Only the
// DECISION lives here, written once; each transport keeps its own
// sent-unit store (QUIC: the per-space `sent_packets` ring with retained
// frames; TCP later: its rtx queue) and drives [`LossParams::detect`] with
// an ascending walk over it.
//
// Ticks are the CALLER's time unit, used consistently across one
// `LossParams` (QUIC passes µs; TCP will pass ms). Pure integer math, zero
// allocation — host-unit-testable like the rest of the crate.

/// RFC 9002 §6.1.1 `kPacketThreshold` (= TCP's classic dupthresh,
/// RFC 5681/6675): a unit trailing the largest acknowledged id by at
/// least this many ids is lost by reordering distance alone.
pub const PACKET_THRESHOLD: u64 = 3;

/// Which threshold declared a unit lost — kept distinct because the two
/// have different failure signatures (a packet-threshold storm points at
/// burst drop / microbursts; a time-threshold storm points at a broken
/// threshold or clock) and the transports count them separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LostBy {
    /// Trails `largest_acked` by ≥ `packet_threshold` ids (RFC 9002
    /// §6.1.1). RTT-independent.
    PacketThreshold,
    /// Older than the time threshold (RFC 9002 §6.1.2 / RACK reordering
    /// window).
    Time,
}

/// One ACK-event's loss-detection parameters: the reordering distance and
/// the RTT-derived age cutoff. Build via [`LossParams::rfc9002`]; fields
/// are public so a transport with different policy (TCP RACK's adaptive
/// reordering window) can set them directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LossParams {
    /// Reordering distance (see [`PACKET_THRESHOLD`]).
    pub packet_threshold: u64,
    /// Age cutoff in caller ticks; a unit strictly older is lost.
    /// `None` while no RTT sample exists — time-based detection is
    /// disabled (an age test against a meaningless threshold would
    /// declare the whole flight lost on the first ACK).
    pub time_threshold_ticks: Option<u64>,
}

impl LossParams {
    /// RFC 9002 §6.1.2 / RACK time threshold, in the caller's ticks:
    ///
    ///   `max(9/8 · max(srtt, latest_rtt), granularity) + max_ack_delay`
    ///
    /// The `+ max_ack_delay` term is load-bearing on a real-RTT path: SRTT
    /// is computed with the peer's ack_delay SUBTRACTED (RFC 9002 §5.3),
    /// but a peer may legitimately hold an ACK up to max_ack_delay, so an
    /// in-order delivered packet's ACK can arrive ~max_ack_delay after
    /// 9/8·SRTT. Without the term those packets were declared time-lost
    /// spuriously (~27 % of a clean transfer at 24 ms RTT), collapsing
    /// cwnd to the floor — the h3 real-RTT throughput bug (task #52). At
    /// low RTT the term is irrelevant (the packet threshold dominates;
    /// ACKs return in µs). WHICH ack delay to pass is transport policy and
    /// stays in the transport: QUIC passes the peer's max_ack_delay for
    /// the Application Data space only (a peer must not delay Initial /
    /// Handshake ACKs, so extending the threshold there would delay real
    /// handshake-loss recovery); TCP passes its delayed-ACK allowance.
    ///
    /// Callers pass `0` for an estimate they don't have yet; with no RTT
    /// sample at all (`srtt == latest_rtt == 0`) time-based detection is
    /// disabled (`time_threshold_ticks = None`).
    pub fn rfc9002(
        srtt_ticks: u64,
        latest_rtt_ticks: u64,
        granularity_ticks: u64,
        max_ack_delay_ticks: u64,
    ) -> Self {
        let max_rtt = srtt_ticks.max(latest_rtt_ticks);
        let time_threshold_ticks = if max_rtt > 0 {
            Some(
                (max_rtt.saturating_mul(9) / 8)
                    .max(granularity_ticks)
                    .saturating_add(max_ack_delay_ticks),
            )
        } else {
            None
        };
        LossParams { packet_threshold: PACKET_THRESHOLD, time_threshold_ticks }
    }

    /// Classify one flight of un-acked units against the thresholds.
    ///
    /// `units` yields `(id, sent_time_ticks)` in ASCENDING id order; the
    /// walk stops at the first `id >= largest_acked` — those are still
    /// plausibly in flight, not reordered (an id never trails itself), so
    /// the unit equal to `largest_acked` is never lost. Each unit strictly
    /// below `largest_acked` is lost by PACKET threshold
    /// (`id + packet_threshold <= largest_acked` — checked first,
    /// RTT-independent), lost by TIME threshold (strictly older than
    /// `time_threshold_ticks`), or not lost yet.
    ///
    /// `lost` is invoked once per lost unit, in ascending id order; the
    /// caller collects ids / counters / retained frames as it needs — the
    /// core allocates nothing. Returns the earliest tick at which a
    /// not-yet-lost unit WILL cross the time threshold
    /// (`sent + threshold + 1` — the age comparison is strict), for the
    /// caller to arm its loss timer with; `None` when no unit awaits a
    /// time verdict. QUIC currently ignores it (it re-runs detection on
    /// the next ACK and PTO covers a silent tail); TCP RACK arms it.
    pub fn detect(
        &self,
        largest_acked: u64,
        now_ticks: u64,
        units: impl IntoIterator<Item = (u64, u64)>,
        mut lost: impl FnMut(u64, LostBy),
    ) -> Option<u64> {
        let mut next_deadline: Option<u64> = None;
        for (id, sent_ticks) in units {
            if id >= largest_acked {
                break;
            }
            if id.saturating_add(self.packet_threshold) <= largest_acked {
                lost(id, LostBy::PacketThreshold);
                continue;
            }
            match self.time_threshold_ticks {
                Some(tt) if now_ticks.saturating_sub(sent_ticks) > tt => {
                    lost(id, LostBy::Time);
                }
                Some(tt) => {
                    let dl = sent_ticks.saturating_add(tt).saturating_add(1);
                    next_deadline = Some(next_deadline.map_or(dl, |d| d.min(dl)));
                }
                None => {}
            }
        }
        next_deadline
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive `detect` over a slice, collecting the lost verdicts.
    fn run(
        p: &LossParams,
        largest_acked: u64,
        now: u64,
        units: &[(u64, u64)],
    ) -> (Vec<(u64, LostBy)>, Option<u64>) {
        let mut lost = Vec::new();
        let dl = p.detect(largest_acked, now, units.iter().copied(), |id, by| {
            lost.push((id, by))
        });
        (lost, dl)
    }

    #[test]
    fn time_threshold_is_nine_eighths_max_rtt_plus_ack_delay() {
        // The mock-clock QUIC scenario: SRTT = latest = 50 ms, 25 ms
        // max_ack_delay → 9/8·50_000 + 25_000 = 81_250.
        let p = LossParams::rfc9002(50_000, 50_000, 1_000, 25_000);
        assert_eq!(p.packet_threshold, PACKET_THRESHOLD);
        assert_eq!(p.time_threshold_ticks, Some(81_250));
        // A latest sample above SRTT dominates (max, not SRTT alone).
        let p = LossParams::rfc9002(50_000, 80_000, 1_000, 0);
        assert_eq!(p.time_threshold_ticks, Some(90_000));
        // And vice versa.
        let p = LossParams::rfc9002(80_000, 50_000, 1_000, 0);
        assert_eq!(p.time_threshold_ticks, Some(90_000));
    }

    #[test]
    fn granularity_floors_the_threshold() {
        // 9/8·400 = 450 < 1000 → floored at the granularity; the
        // ack_delay term still adds on top of the floor.
        let p = LossParams::rfc9002(400, 0, 1_000, 25_000);
        assert_eq!(p.time_threshold_ticks, Some(26_000));
        let p = LossParams::rfc9002(400, 0, 1_000, 0);
        assert_eq!(p.time_threshold_ticks, Some(1_000));
    }

    #[test]
    fn no_rtt_sample_disables_time_detection() {
        let p = LossParams::rfc9002(0, 0, 1_000, 25_000);
        assert_eq!(p.time_threshold_ticks, None);
        // A unit of any age within the packet threshold stays NotLost and
        // arms no deadline — there's no threshold to cross.
        let (lost, dl) = run(&p, 1, 1_000_000_000, &[(0, 0)]);
        assert!(lost.is_empty(), "no time verdicts without an RTT sample");
        assert_eq!(dl, None);
    }

    #[test]
    fn packet_threshold_classifies_by_reordering_distance() {
        let p = LossParams::rfc9002(50_000, 50_000, 1_000, 25_000);
        // largest_acked = 10, all units fresh (no time loss possible):
        // ids 5..=7 satisfy id + 3 <= 10 → lost; 8 and 9 trail by less.
        let now = 1_000_000;
        let units: Vec<(u64, u64)> = (5..=9).map(|id| (id, now)).collect();
        let (lost, _) = run(&p, 10, now, &units);
        assert_eq!(
            lost,
            vec![
                (5, LostBy::PacketThreshold),
                (6, LostBy::PacketThreshold),
                (7, LostBy::PacketThreshold),
            ]
        );
    }

    #[test]
    fn time_threshold_classifies_by_age() {
        // The mock-clock QUIC timeline: threshold 81 250 µs; a unit 1 id
        // behind (below the packet threshold) is lost iff strictly older.
        let p = LossParams::rfc9002(50_000, 50_000, 1_000, 25_000);
        let sent = 1_000_000u64;
        // Age 100 ms > 81.25 ms → lost by time.
        let (lost, dl) = run(&p, 1, sent + 100_000, &[(0, sent)]);
        assert_eq!(lost, vec![(0, LostBy::Time)]);
        assert_eq!(dl, None, "nothing left awaiting a time verdict");
        // Age 51 ms < threshold → reordered, NOT lost (the §52 negative).
        let (lost, _) = run(&p, 1, sent + 51_000, &[(0, sent)]);
        assert!(lost.is_empty(), "young reordering must not be loss");
        // Age exactly the threshold → still not lost (comparison strict).
        let (lost, _) = run(&p, 1, sent + 81_250, &[(0, sent)]);
        assert!(lost.is_empty(), "age == threshold is not yet loss");
    }

    #[test]
    fn deadline_is_the_first_tick_the_unit_becomes_lost() {
        let p = LossParams::rfc9002(50_000, 50_000, 1_000, 25_000);
        let sent = 2_000_000u64;
        let (lost, dl) = run(&p, 1, sent + 10_000, &[(0, sent)]);
        assert!(lost.is_empty());
        let dl = dl.expect("a pending unit arms the loss deadline");
        assert_eq!(dl, sent + 81_250 + 1);
        // Self-consistency: re-running at deadline−1 keeps it in flight;
        // at the deadline it flips to lost — so a timer armed at `dl`
        // never fires early and never misses.
        let (lost, _) = run(&p, 1, dl - 1, &[(0, sent)]);
        assert!(lost.is_empty(), "one tick early: still in flight");
        let (lost, _) = run(&p, 1, dl, &[(0, sent)]);
        assert_eq!(lost, vec![(0, LostBy::Time)], "at the deadline: lost");
    }

    #[test]
    fn earliest_deadline_wins_across_pending_units() {
        let p = LossParams::rfc9002(50_000, 50_000, 1_000, 25_000);
        // Two units below largest_acked but inside both thresholds; the
        // older one's deadline is the earlier and must be the one returned.
        let (lost, dl) = run(&p, 3, 1_060_000, &[(1, 1_000_000), (2, 1_050_000)]);
        assert!(lost.is_empty());
        assert_eq!(dl, Some(1_000_000 + 81_250 + 1));
    }

    #[test]
    fn unit_at_largest_acked_is_never_lost() {
        // The ordering edge: id == largest_acked stops the walk — an id
        // never trails itself, however ancient its send time (and ids
        // above it are still in flight, equally untouchable).
        let p = LossParams::rfc9002(50_000, 50_000, 1_000, 0);
        let (lost, dl) = run(&p, 5, u64::MAX, &[(5, 0), (6, 0)]);
        assert!(lost.is_empty(), "id == largest_acked must never be lost");
        assert_eq!(dl, None, "the walk stops before arming any deadline");
    }
}
