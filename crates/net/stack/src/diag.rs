// crates/net/stack/src/diag.rs — observability for the L2/L3 RX dispatch.
//
// The observability doctrine (`docs/observability.md`) applied to
// the network stack's frame-dispatch layer (`rx.rs`). Frames arrive
// from the NIC, get classified (eth + L3 parse), and are routed to
// a transport handler — or dropped. The drops were silent: a
// `Classified::Drop` and the `deliver` no-handler arm both fell
// through to `{}`. This module counts them and snapshots what the
// stack is dropping. Surfaced as the `"net"` block of `/obs` via
// `waitless_backend::net_obs_json`.

use core::fmt;

use obs::{Counter, LastEvent, ObsRecord};

/// L2/L3 RX-dispatch counters.
pub struct Counters {
    /// Inbound frames the classifier rejected before L4 — not
    /// addressed to us, an unknown EtherType, or a malformed
    /// L2/L3 header (`Classified::Drop`). Silent before this counter.
    pub classified_drops: Counter,
    /// Fully-parsed IP frames carrying an L4 protocol the stack has
    /// no handler for — not TCP / UDP / ICMPv6. Dropped after the
    /// L3 parse; also silent before now.
    pub unknown_l4: Counter,
    /// PMTUD reports that missed this core's connection table and were
    /// broadcast over the cross-core control lane (one bump per
    /// report, not per recipient). Whether the owner then applied or
    /// rejected it shows up in tcp's `pmtu_applied` / `pmtu_dropped`.
    pub pmtu_routed: Counter,
    /// Control-lane sends dropped because the shared node pool was
    /// momentarily exhausted — should stay 0 (messages are rare and
    /// drained every loop); a climbing value means a producer is
    /// flooding the lane.
    pub ctrl_dropped: Counter,
}

impl Counters {
    const fn new() -> Self {
        Counters {
            classified_drops: Counter::new(),
            unknown_l4: Counter::new(),
            pmtu_routed: Counter::new(),
            ctrl_dropped: Counter::new(),
        }
    }
}

/// Process-wide L2/L3 dispatch counters.
pub static COUNTERS: Counters = Counters::new();

/// Most recent frame the classifier dropped — what is the stack
/// turning away?
pub static LAST_CLASSIFIED_DROP: LastEvent<ClassifiedDropRecord> = LastEvent::new();

/// Snapshot payload for `LAST_CLASSIFIED_DROP`.
#[derive(Clone, Copy)]
pub struct ClassifiedDropRecord {
    /// EtherType from the L2 header (bytes 12-13), or `0` if the
    /// frame was too short to carry one.
    pub ethertype: u16,
    /// Frame length, capped at `u16::MAX`.
    pub len: u16,
}

impl ObsRecord for ClassifiedDropRecord {
    fn write_fields(&self, w: &mut dyn fmt::Write) -> fmt::Result {
        write!(w, "\"ethertype\":{},\"len\":{}", self.ethertype, self.len)
    }
}

/// Record a classifier drop: bump `classified_drops` and snapshot
/// the frame's EtherType + length into `LAST_CLASSIFIED_DROP`.
pub fn record_classified_drop(frame: &[u8]) {
    COUNTERS.classified_drops.bump();
    let ethertype = if frame.len() >= 14 {
        u16::from_be_bytes([frame[12], frame[13]])
    } else {
        0
    };
    LAST_CLASSIFIED_DROP.record(ClassifiedDropRecord {
        ethertype,
        len: frame.len().min(u16::MAX as usize) as u16,
    });
}

/// Counter `(name, value)` pairs in declaration order.
pub fn snapshot() -> [(&'static str, u64); 4] {
    let c = &COUNTERS;
    [
        ("classified_drops", c.classified_drops.get()),
        ("unknown_l4", c.unknown_l4.get()),
        ("pmtu_routed", c.pmtu_routed.get()),
        ("ctrl_dropped", c.ctrl_dropped.get()),
    ]
}

/// Render the L2/L3-dispatch observability block as a JSON object.
/// This is the network stack's `/obs` block.
pub fn write_obs_json(w: &mut dyn fmt::Write) -> fmt::Result {
    w.write_str("{")?;
    for (name, value) in snapshot() {
        write!(w, "\"{name}\":{value},")?;
    }
    LAST_CLASSIFIED_DROP.write_json(w, "last_classified_drop")?;
    w.write_str("}")
}
