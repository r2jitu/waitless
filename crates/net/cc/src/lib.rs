// net/cc — shared congestion-control core (the "transport reliability
// plane" seam from docs/stack-architecture.md and docs/tx-backpressure.md).
//
// One [`CongestionControl`] trait, driven identically by TCP and QUIC, so
// the slow-start + AIMD + recovery window algorithm is written ONCE rather
// than twice. RFC 9002's recommended QUIC controller is NewReno — the same
// math as TCP Reno (RFC 5681) — so [`NewReno`] here serves both:
//   * QUIC gets its first congestion controller (closes RFC 9002 step 5 —
//     today it detects loss but has no window to shrink).
//   * TCP can delegate its embedded `cwnd`/`ssthresh` methods to the trait.
//
// This is the per-flow back-pressure source (a slow/lossy *path or peer*):
// it bounds a connection's in-flight bytes to `window()`, which is also the
// in-flight memory bound that lets a bounded, ACK-released send buffer keep
// total per-connection memory finite. The *other* back-pressure source —
// many flows saturating one NIC egress — is the egress scheduler's job, not
// this trait's (see docs/tx-backpressure.md).
//
// Pure integer state, no alloc, no device deps → host-unit-testable.

#![cfg_attr(not(test), no_std)]

/// Round-trip-time inputs the controller needs. Transports keep their own
/// RTT *estimators* (TCP RFC 6298, QUIC RFC 9002 with `ack_delay`/`min_rtt`
/// differ enough that sharing is low-value) and hand the controller just
/// the smoothed and minimum samples it uses for pacing.
#[derive(Clone, Copy, Debug)]
pub struct Rtt {
    /// Smoothed RTT in microseconds (the transport's SRTT).
    pub smoothed_us: u32,
    /// Minimum observed RTT in microseconds (for BBR-style work later;
    /// NewReno's pacer uses `smoothed_us`).
    pub min_us: u32,
}

impl Rtt {
    pub const fn new(smoothed_us: u32, min_us: u32) -> Self {
        Rtt { smoothed_us, min_us }
    }
}

/// One window/pacing controller, driven by both transports. Reno/CUBIC/BBR
/// implement this once; the transport supplies the loss/ack events and the
/// RTT, and reads back `window()` (the in-flight cap) and `pacing_rate()`
/// (for the shared pacer).
pub trait CongestionControl {
    /// `bytes_acked` newly-acknowledged bytes; `in_flight` is the bytes
    /// still unacknowledged *after* this ack is applied by the caller; `rtt`
    /// the current estimate. Grows the window (slow start or AIMD).
    fn on_ack(&mut self, bytes_acked: u32, in_flight: u32, rtt: Rtt);

    /// A loss was declared (`bytes_lost` bytes). `persistent` = persistent
    /// congestion (RFC 9002 §7.6 / repeated RTO): collapse to the minimum
    /// window. A normal loss halves the window, but only once per recovery
    /// episode (further losses in the same window are ignored).
    fn on_loss(&mut self, bytes_lost: u32, persistent: bool);

    /// Retransmission timeout (TCP RTO) / confirmed PTO loss. Equivalent to
    /// `on_loss(.., persistent = true)`.
    fn on_rto(&mut self);

    /// Current congestion window, in bytes — the cap on in-flight data.
    fn window(&self) -> u32;

    /// Target send rate in bytes/s for the shared pacer (0 = unpaced).
    fn pacing_rate(&self) -> u64;

    /// Convenience: may `bytes` more be put in flight without exceeding the
    /// window? The single predicate every send path checks for source-#1
    /// back-pressure.
    fn can_send(&self, in_flight: u32, bytes: u32) -> bool {
        in_flight.saturating_add(bytes) <= self.window()
    }
}

/// Default maximum segment / datagram payload assumed when none is given.
/// 1200 is QUIC's conservative floor; TCP passes its negotiated MSS.
pub const DEFAULT_MSS: u32 = 1200;

/// RFC 9002 §7.2 recommended initial window: `min(10·MSS, max(2·MSS, 14600))`.
pub const fn initial_window(mss: u32) -> u32 {
    let ten = mss.saturating_mul(10);
    let floor = max_u32(mss.saturating_mul(2), 14_600);
    min_u32(ten, floor)
}

/// RFC 9002 §7.2 minimum congestion window: `2·MSS`.
pub const fn minimum_window(mss: u32) -> u32 {
    mss.saturating_mul(2)
}

/// Default maximum congestion window (cap on bytes-in-flight). RFC 9002
/// places no upper bound on cwnd — it's normally limited by the receiver
/// flow-control window — but a sender that retains in-flight data for
/// retransmission must cap it to bound memory, and a peer that auto-tunes
/// a huge receive window (or a fast lossless path where slow-start grows
/// cwnd without bound before any loss) would otherwise let in-flight grow
/// until the heap is exhausted. 2 MiB is ample throughput on low-RTT paths
/// (2 MiB / 0.1 ms ≈ 20 GB/s) and bounds per-connection send memory.
pub const DEFAULT_MAX_WINDOW: u32 = 2 << 20;

const fn min_u32(a: u32, b: u32) -> u32 {
    if a < b { a } else { b }
}
const fn max_u32(a: u32, b: u32) -> u32 {
    if a > b { a } else { b }
}

/// NewReno (RFC 5681 / RFC 9002 §7): slow start until `cwnd >= ssthresh`,
/// then additive-increase (~1 MSS/RTT); multiplicative-decrease (halve) on
/// loss, once per recovery episode; collapse to the minimum window on
/// persistent congestion / RTO.
#[derive(Clone, Copy, Debug)]
pub struct NewReno {
    mss: u32,
    cwnd: u32,
    ssthresh: u32,
    /// In a recovery episode → ignore further loss reductions (RFC 9002
    /// §7.3.2: at most one cwnd reduction per congestion event). The episode
    /// ends only after `recovery_rem_bytes` of NEW data is acknowledged
    /// (≈ one window ≈ one RTT — i.e. packets sent after recovery started are
    /// now being acked), NOT on the next ack. Resetting on every ack (the old
    /// behaviour) let a cluster of losses within one RTT halve cwnd once per
    /// loss → collapse to the minimum window on a real-RTT path where acks
    /// arrive several times per RTT (the h3 real-RTT throughput bug).
    in_recovery: bool,
    /// Bytes of fresh acks still required to exit the current recovery
    /// episode. Set to the pre-reduction cwnd on entry; decremented by
    /// `on_ack`. Meaningless when `in_recovery` is false.
    recovery_rem_bytes: u32,
    /// Last smoothed RTT (µs) seen on an ack, for `pacing_rate`.
    srtt_us: u32,
    /// Upper bound on `cwnd` (and thus bytes-in-flight). See
    /// [`DEFAULT_MAX_WINDOW`].
    max_window: u32,
    /// Per-ACK slow-start increment cap, bytes — RFC 3465 ABC's `L`
    /// (`min(bytes_acked, L)` per ACK). `0` = uncapped. The cap bounds the
    /// burst a single stretch-ACK / post-idle ACK releases on an *unpaced*
    /// sender (TCP sets `L = 2·MSS`); a paced sender (QUIC) leaves it 0
    /// because the pacer is the burst guard.
    slow_start_cap: u32,
}

impl NewReno {
    pub const fn new(mss: u32) -> Self {
        let mss = if mss == 0 { DEFAULT_MSS } else { mss };
        NewReno {
            mss,
            cwnd: initial_window(mss),
            // Start ssthresh "infinite" so the connection begins in slow
            // start (RFC 5681 §3.1).
            ssthresh: u32::MAX,
            in_recovery: false,
            recovery_rem_bytes: 0,
            srtt_us: 0,
            max_window: max_u32(DEFAULT_MAX_WINDOW, initial_window(mss)),
            slow_start_cap: 0,
        }
    }

    /// Default-MSS constructor.
    pub const fn with_default_mss() -> Self {
        Self::new(DEFAULT_MSS)
    }

    /// Override the maximum congestion window (see [`DEFAULT_MAX_WINDOW`]).
    /// Clamped to at least the initial window.
    pub fn set_max_window(&mut self, max: u32) {
        self.max_window = max_u32(max, initial_window(self.mss));
    }

    /// Set the per-ACK slow-start increment cap (RFC 3465 ABC `L`); `0`
    /// disables it. Unpaced senders (TCP) set `2·MSS`; paced senders leave
    /// it 0.
    pub fn set_slow_start_cap(&mut self, cap: u32) {
        self.slow_start_cap = cap;
    }

    pub fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    pub fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// Halve the window into recovery (RFC 5681 §3.1 / RFC 9002 §7.3.2):
    /// `ssthresh = cwnd/2` (≥ min), `cwnd = ssthresh`.
    fn enter_recovery(&mut self) {
        // The recovery period ends once ~one window of new data is acked
        // (≈ one RTT). Anchor it to the pre-reduction cwnd.
        self.recovery_rem_bytes = max_u32(self.cwnd, minimum_window(self.mss));
        let half = self.cwnd / 2;
        self.ssthresh = max_u32(half, minimum_window(self.mss));
        self.cwnd = self.ssthresh;
        self.in_recovery = true;
    }
}

impl CongestionControl for NewReno {
    fn on_ack(&mut self, bytes_acked: u32, _in_flight: u32, rtt: Rtt) {
        if rtt.smoothed_us != 0 {
            self.srtt_us = rtt.smoothed_us;
        }
        if bytes_acked == 0 {
            return;
        }
        // Recovery period (RFC 9002 §7.3.2): hold cwnd — neither grow nor
        // reduce again — until ~one window of new data is acked, which marks
        // the recovery-triggering congestion event as past. Only THEN may a
        // later loss reduce cwnd again. (Counting acked bytes ≈ "a packet
        // sent after recovery started has been acked" without packet numbers.)
        if self.in_recovery {
            self.recovery_rem_bytes = self.recovery_rem_bytes.saturating_sub(bytes_acked);
            if self.recovery_rem_bytes == 0 {
                self.in_recovery = false;
            }
            return;
        }
        if self.in_slow_start() {
            // Slow start: exponential — one window per RTT. Byte-counting
            // (RFC 9002 §7.3.1), capped so we land exactly on ssthresh, and
            // — for an unpaced sender — by the optional RFC 3465 `L` burst
            // cap (`slow_start_cap`, 0 = off).
            let room = self.ssthresh.saturating_sub(self.cwnd);
            let mut inc = min_u32(bytes_acked, room);
            if self.slow_start_cap != 0 {
                inc = min_u32(inc, self.slow_start_cap);
            }
            self.cwnd = self.cwnd.saturating_add(inc);
            // If room was 0 (already at ssthresh) we fall through to CA on
            // the next ack; nothing more to do here.
        } else {
            // Congestion avoidance: additive increase of ~MSS per RTT, i.e.
            // `cwnd += MSS * bytes_acked / cwnd` (RFC 5681 §3.1 eq. 2 /
            // RFC 9002 §7.3.2). Integer form; never below 1 byte of growth
            // once a full cwnd is acked.
            let inc = (self.mss as u64 * bytes_acked as u64 / self.cwnd as u64) as u32;
            self.cwnd = self.cwnd.saturating_add(inc.max(1));
        }
        // Cap the window so bytes-in-flight (and any per-packet data a
        // sender retains for retransmission) can't grow without bound on a
        // lossless / large-receive-window path. See `DEFAULT_MAX_WINDOW`.
        self.cwnd = min_u32(self.cwnd, self.max_window);
    }

    fn on_loss(&mut self, _bytes_lost: u32, persistent: bool) {
        if persistent {
            // RFC 9002 §7.6: collapse to the minimum window and restart slow
            // start from there.
            self.ssthresh = self.cwnd / 2;
            self.ssthresh = max_u32(self.ssthresh, minimum_window(self.mss));
            self.cwnd = minimum_window(self.mss);
            self.recovery_rem_bytes = self.cwnd;
            self.in_recovery = true;
            return;
        }
        if self.in_recovery {
            // Already reduced for this window — one halving per episode.
            return;
        }
        self.enter_recovery();
    }

    fn on_rto(&mut self) {
        self.on_loss(0, true);
    }

    fn window(&self) -> u32 {
        // Clamped to `[minimum_window, max_window]`.
        min_u32(max_u32(self.cwnd, minimum_window(self.mss)), self.max_window)
    }

    fn pacing_rate(&self) -> u64 {
        if self.srtt_us == 0 {
            return 0; // no RTT sample yet → let the caller send IW unpaced
        }
        // RFC 9002 §7.7: pacing_rate = N * cwnd / smoothed_rtt. N = 5/4 in
        // congestion avoidance, 2 in slow start (drain faster while probing).
        let n_num: u64 = if self.in_slow_start() { 2 } else { 5 };
        let n_den: u64 = if self.in_slow_start() { 1 } else { 4 };
        let cwnd = self.window() as u64;
        // bytes/s = cwnd * 1e6 / srtt_us, scaled by N.
        cwnd.saturating_mul(1_000_000)
            .saturating_mul(n_num)
            / (self.srtt_us as u64 * n_den)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSS: u32 = 1200;
    fn rtt() -> Rtt {
        Rtt::new(50_000, 50_000) // 50 ms
    }

    #[test]
    fn initial_window_rfc9002() {
        // min(10*MSS, max(2*MSS, 14600)). For MSS=1200: 10*1200=12000,
        // max(2400,14600)=14600 → min(12000,14600)=12000.
        assert_eq!(initial_window(1200), 12_000);
        // For a large MSS the 14600 floor binds: MSS=4000 → 10*4000=40000,
        // max(8000,14600)=14600 → 14600.
        assert_eq!(initial_window(4000), 14_600);
        assert_eq!(minimum_window(1200), 2400);
    }

    #[test]
    fn starts_in_slow_start_at_iw() {
        let cc = NewReno::new(MSS);
        assert!(cc.in_slow_start());
        assert_eq!(cc.window(), initial_window(MSS));
    }

    #[test]
    fn slow_start_is_exponential() {
        let mut cc = NewReno::new(MSS);
        let start = cc.window();
        // Ack a full window worth of bytes → cwnd should ~double (one
        // window per RTT in slow start).
        cc.on_ack(start, 0, rtt());
        assert_eq!(cc.window(), start * 2);
    }

    #[test]
    fn loss_halves_once_per_episode() {
        let mut cc = NewReno::new(MSS);
        // Grow a bit first.
        cc.on_ack(cc.window(), 0, rtt());
        let before = cc.window();
        cc.on_loss(MSS, false);
        let after = cc.window();
        assert_eq!(after, max_u32(before / 2, minimum_window(MSS)));
        // A second loss in the same episode (no intervening ack) must NOT
        // halve again.
        cc.on_loss(MSS, false);
        assert_eq!(cc.window(), after);
        // A SINGLE ack must NOT end the recovery period (the real-RTT bug: at
        // several acks per RTT, that let a loss cluster halve once per loss).
        cc.on_ack(MSS, 0, rtt());
        cc.on_loss(MSS, false);
        assert_eq!(cc.window(), after, "one ack must not reopen reductions");
        // Only after ~a full window of acks does the episode end; a fresh loss
        // then reduces again (a new congestion event).
        let mut acked = 0;
        while acked < before {
            cc.on_ack(MSS, 0, rtt());
            acked += MSS;
        }
        let grown = cc.window();
        cc.on_loss(MSS, false);
        assert!(cc.window() < grown, "a new event after recovery reduces cwnd");
    }

    #[test]
    fn congestion_avoidance_is_additive() {
        let mut cc = NewReno::new(MSS);
        // Force into congestion avoidance via a loss (sets ssthresh<=cwnd).
        cc.on_ack(cc.window(), 0, rtt());
        let pre = cc.window();
        cc.on_loss(MSS, false);
        // Drain the recovery period (~one pre-loss window of acks) so cwnd is
        // free to grow again; now cwnd>=ssthresh → CA.
        let mut drain = 0;
        while drain < pre {
            cc.on_ack(MSS, 0, rtt());
            drain += MSS;
        }
        assert!(!cc.in_slow_start());
        let w0 = cc.window();
        // Acking ~one full window should add ~one MSS (additive increase).
        let mut acked = 0;
        while acked < w0 {
            cc.on_ack(MSS, 0, rtt());
            acked += MSS;
        }
        let grew = cc.window() - w0;
        // ~1 MSS per RTT (allow slack for integer rounding across the loop).
        assert!((MSS / 2..=2 * MSS).contains(&grew), "grew={grew} mss={MSS}");
    }

    #[test]
    fn persistent_congestion_collapses_to_min() {
        let mut cc = NewReno::new(MSS);
        cc.on_ack(cc.window() * 4, 0, rtt()); // grow
        cc.on_loss(MSS, true);
        assert_eq!(cc.window(), minimum_window(MSS));
        // RTO is the same.
        let mut cc2 = NewReno::new(MSS);
        cc2.on_ack(cc2.window() * 4, 0, rtt());
        cc2.on_rto();
        assert_eq!(cc2.window(), minimum_window(MSS));
    }

    #[test]
    fn window_never_below_floor() {
        let mut cc = NewReno::new(MSS);
        for _ in 0..20 {
            cc.on_loss(MSS, true);
        }
        assert_eq!(cc.window(), minimum_window(MSS));
    }

    #[test]
    fn window_capped_at_max() {
        let mut cc = NewReno::new(MSS);
        // Slow start would otherwise grow the window without bound on a
        // lossless path; the cap must hold.
        for _ in 0..40 {
            let w = cc.window();
            cc.on_ack(w, 0, rtt());
        }
        assert_eq!(cc.window(), DEFAULT_MAX_WINDOW);
        // A lower override is honored (clamped to ≥ initial window).
        cc.set_max_window(64 * 1024);
        assert!(cc.window() <= 64 * 1024);
    }

    #[test]
    fn can_send_gates_on_window() {
        let cc = NewReno::new(MSS);
        let w = cc.window();
        assert!(cc.can_send(0, w));
        assert!(cc.can_send(w - MSS, MSS));
        assert!(!cc.can_send(w, 1));
        assert!(!cc.can_send(w - 1, 2));
    }

    #[test]
    fn pacing_rate_scales_with_cwnd_over_rtt() {
        let mut cc = NewReno::new(MSS);
        assert_eq!(cc.pacing_rate(), 0); // no RTT sample yet
        cc.on_ack(MSS, 0, rtt());
        let r1 = cc.pacing_rate();
        assert!(r1 > 0);
        // Bigger cwnd (more acks) → higher rate at the same RTT.
        cc.on_ack(cc.window(), 0, rtt());
        assert!(cc.pacing_rate() > r1);
    }

    /// Regression for the h3 real-RTT collapse (task #52): a burst of losses
    /// interleaved with the many acks-per-RTT a real RTT produces must reduce
    /// cwnd ONCE for the episode, not once per loss. The old code reset
    /// recovery on every ack, so this sequence drove cwnd to the floor.
    #[test]
    fn clustered_losses_with_acks_reduce_once() {
        let mut cc = NewReno::new(MSS);
        // Grow into a healthy window.
        for _ in 0..6 {
            let w = cc.window();
            cc.on_ack(w, 0, rtt());
        }
        let pre = cc.window();
        assert!(pre > 8 * minimum_window(MSS), "need headroom to see a collapse");
        // One congestion event spread across an RTT: losses interleaved with
        // small acks (as a real-RTT flow sees). cwnd must halve at most once.
        for _ in 0..20 {
            cc.on_loss(MSS, false);
            cc.on_ack(MSS, 0, rtt()); // a few packets ack within the same RTT
        }
        let after = cc.window();
        // Exactly one halving (to ssthresh), NOT a collapse to the floor.
        assert_eq!(after, max_u32(pre / 2, minimum_window(MSS)));
        assert!(
            after > minimum_window(MSS),
            "cwnd collapsed to the floor: {after} (regression)"
        );
    }

    #[test]
    fn slow_start_cap_bounds_the_per_ack_increment() {
        // Unpaced-sender cap (RFC 3465 L = 2·MSS): a stretch-ACK acking 10
        // segments must open cwnd by at most 2·MSS, not 10·MSS.
        let mut cc = NewReno::new(MSS);
        cc.set_slow_start_cap(2 * MSS);
        let before = cc.window();
        cc.on_ack(10 * MSS, 0, rtt());
        assert_eq!(cc.window(), before + 2 * MSS, "stretch-ACK capped at 2·MSS");
        // Uncapped (paced default): the same stretch-ACK opens by the full
        // bytes acked (still bounded by room-to-ssthresh, here effectively
        // infinite at start).
        let mut paced = NewReno::new(MSS);
        let before = paced.window();
        paced.on_ack(10 * MSS, 0, rtt());
        assert_eq!(paced.window(), before + 10 * MSS, "uncapped grows by bytes acked");
    }
}
