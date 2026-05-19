// net/l4_tx.rs — outbound L4 (TCP/UDP) checksum stamping.
//
// `tcp.rs` and `udp.rs` both decide what to write into an outbound
// segment's checksum field, and the decision is identical: it turns
// on the active NIC's CSUM-offload convention, not on the L4
// protocol. This crate owns that one decision so the TCP frame
// builder and the UDP send path don't each carry a copy.

#![no_std]

extern crate net_types as types;
extern crate uni_drivers;

use types::IpAddr;

/// The value to stamp into an outbound TCP/UDP segment's checksum
/// field. `src`/`dst` are the L3 addresses; `seg` / `seg_len`
/// describe the L4 segment (header + payload).
///
///   * Offload available (`csum_tx_offload`): the pseudo-header
///     partial sum — the device adds the payload and folds.
///   * No offload: the full checksum, computed guest-side (the
///     only branch that reads `seg`).
///
/// `seg` is a raw pointer rather than `&[u8]` because callers
/// compute this while holding a live `&mut` to the segment's header
/// — an overlapping `&[u8]` would alias it. It is read only on the
/// no-offload branch, and only for `seg_len` bytes.
pub fn checksum(src: IpAddr, dst: IpAddr, proto: u8, seg: *const u8, seg_len: usize) -> u16 {
    if uni_drivers::net::csum_tx_offload() {
        types::l4_pseudo_partial(src, dst, proto, seg_len)
    } else {
        types::l4_checksum_any(src, dst, proto, seg, seg_len)
    }
}
