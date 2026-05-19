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
/// field, per the active NIC's CSUM-offload convention. `src`/`dst`
/// are the L3 addresses; `seg` / `seg_len` describe the L4 segment
/// (header + payload).
///
///   * Offload, pseudo-header-partial (virtio): the partial sum
///     over just the pseudo-header — the device sums the rest.
///   * Offload, zero (gve): `0` — the device builds the whole
///     checksum, pseudo-header included.
///   * No offload: the full checksum, computed guest-side (the only
///     branch that reads `seg`).
///
/// `seg` is a raw pointer rather than `&[u8]` because callers
/// compute this while holding a live `&mut` to the segment's header
/// — an overlapping `&[u8]` would alias it. It is read only on the
/// no-offload branch, and only for `seg_len` bytes.
pub fn checksum(src: IpAddr, dst: IpAddr, proto: u8, seg: *const u8, seg_len: usize) -> u16 {
    if uni_drivers::net::csum_tx_offload() {
        match uni_drivers::net::csum_stamp_convention() {
            uni_drivers::net::CsumStampConvention::PseudoHeaderPartial => {
                types::l4_pseudo_partial(src, dst, proto, seg_len)
            }
            uni_drivers::net::CsumStampConvention::Zero => 0,
        }
    } else {
        types::l4_checksum_any(src, dst, proto, seg, seg_len)
    }
}
