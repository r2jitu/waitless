// net/udp.rs — UDP send/receive.
//
// Simple datagram protocol — no state machine, no connection
// tracking. The async reactor (`executor::reactor::UdpSocket`) is
// the only binder these days; the pre-async `bind(port, handler)`
// sync-callback registry is gone.

#![no_std]

extern crate net_checksum as checksum;
extern crate net_from_bytes as from_bytes;
extern crate net_types as types;

use from_bytes::FromBytes;
use types::{CONFIG, IpAddr, MacAddr, htons, ntohs};

/// Observability for the UDP path — the observability doctrine
/// (`docs/observability.md`) applied to a stateless protocol. No
/// state machine, so this is event counters plus one "last
/// undeliverable datagram" snapshot. Surfaced as the `"udp"` block
/// of `/obs` via `waitless_backend::udp_obs_json`.
pub mod diag {
    use core::fmt;
    use obs::{Counter, LastEvent, ObsRecord};

    /// One counter per UDP event.
    pub struct Counters {
        /// Datagrams that parsed and were delivered to a bound socket.
        pub rx_datagrams: Counter,
        /// Datagrams dropped at parse — short/garbage header or a
        /// `length` field inconsistent with the segment.
        pub rx_malformed: Counter,
        /// Well-formed datagrams dropped because no socket was bound
        /// to the destination port (`deliver_udp` returned false).
        /// `LAST_UNDELIVERABLE` has the port.
        pub rx_undeliverable: Counter,
        /// Datagrams shipped to the wire.
        pub tx_datagrams: Counter,
        /// Sends dropped because the destination MAC was unresolved
        /// (ARP / NDP miss). UDP is fire-and-forget — the app layer
        /// retransmits.
        pub tx_mac_unresolved: Counter,
        /// Sends dropped for an invalid payload size (empty, or
        /// past the single-frame MTU).
        pub tx_invalid: Counter,
    }

    impl Counters {
        const fn new() -> Self {
            Counters {
                rx_datagrams: Counter::new(),
                rx_malformed: Counter::new(),
                rx_undeliverable: Counter::new(),
                tx_datagrams: Counter::new(),
                tx_mac_unresolved: Counter::new(),
                tx_invalid: Counter::new(),
            }
        }
    }

    /// Process-wide UDP counters.
    pub static COUNTERS: Counters = Counters::new();

    /// Most recent datagram dropped for want of a bound socket.
    pub static LAST_UNDELIVERABLE: LastEvent<UndeliverableRecord> = LastEvent::new();

    /// Snapshot payload for `LAST_UNDELIVERABLE`.
    #[derive(Clone, Copy)]
    pub struct UndeliverableRecord {
        pub dst_port: u16,
        pub src_port: u16,
        pub len: u16,
        pub at_ms: u64,
    }

    impl ObsRecord for UndeliverableRecord {
        fn write_fields(&self, w: &mut dyn fmt::Write) -> fmt::Result {
            write!(
                w,
                "\"dst_port\":{},\"src_port\":{},\"len\":{},\"at_ms\":{}",
                self.dst_port, self.src_port, self.len, self.at_ms,
            )
        }
    }

    /// Record an undeliverable datagram: bump the counter and
    /// snapshot the destination port into `LAST_UNDELIVERABLE`.
    pub fn record_undeliverable(dst_port: u16, src_port: u16, len: usize) {
        COUNTERS.rx_undeliverable.bump();
        LAST_UNDELIVERABLE.record(UndeliverableRecord {
            dst_port,
            src_port,
            len: len.min(u16::MAX as usize) as u16,
            at_ms: kernel_core::clock::now_ms(),
        });
    }

    /// Counter `(name, value)` pairs in declaration order.
    pub fn snapshot() -> [(&'static str, u64); 6] {
        let c = &COUNTERS;
        [
            ("rx_datagrams", c.rx_datagrams.get()),
            ("rx_malformed", c.rx_malformed.get()),
            ("rx_undeliverable", c.rx_undeliverable.get()),
            ("tx_datagrams", c.tx_datagrams.get()),
            ("tx_mac_unresolved", c.tx_mac_unresolved.get()),
            ("tx_invalid", c.tx_invalid.get()),
        ]
    }

    /// Render the UDP observability block as a JSON object.
    pub fn write_obs_json(w: &mut dyn fmt::Write) -> fmt::Result {
        w.write_str("{")?;
        for (name, value) in snapshot() {
            write!(w, "\"{name}\":{value},")?;
        }
        LAST_UNDELIVERABLE.write_json(w, "last_undeliverable")?;
        w.write_str("}")
    }
}

#[repr(C, packed)]
struct UdpHeader {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
}

// SAFETY: repr(C, packed), all fields u16.
unsafe impl FromBytes for UdpHeader {}

/// Backend send entrypoint registered with the runtime
/// `UdpBackend` vtable. Forwards to `send_to_addr`. Kept as a
/// thin wrapper so the runtime sees a stable function pointer
/// signature even if `send_to_addr` evolves.
pub fn send(dst_ip: IpAddr, src_port: u16, dst_port: u16, data: &[u8]) {
    send_to_addr(dst_ip, src_port, dst_port, data);
}

// ─── Unified UDP-frame builder ───────────────────────────────────────────────
//
// `send_with_l2_headroom` is the single primitive: caller hands a
// frame buffer with MAX_L2_HEADROOM = 62 B reserved at the front,
// payload at `frame[MAX_L2_HEADROOM..]`. Fills the L2/L3/L4
// headers in place and ships the contiguous frame to the driver —
// no payload memcpy, replacing the legacy chain of
// `send_to_addr → ipv4_send → ethernet_send` (3 wrap memcpys per
// byte).
//
// `send_to_addr` is the slice-shaped wrapper that pre-existing
// callers (UdpSocket::send_to, DHCP, ICMP-piggyback) still use.
// It does one memcpy of the payload into a stack frame and calls
// the headroom primitive — same total memcpy count as the
// legacy 3-stack-buf path, but consolidated into one site.
//
// Frame layout:
//   v4: [ETH 14][IPv4 20][UDP 8][payload ≤ 1472]  → ≤ 1514 B
//   v6: [ETH 14][IPv6 40][UDP 8][payload ≤ 1452]  → ≤ 1514 B

const ETH_HDR_LEN: usize = ethernet::HEADER_LEN; // 14
const IPV4_HDR_LEN: usize = ipv4::HEADER_LEN; // 20
const IPV6_HDR_LEN: usize = ipv6::HEADER_LEN; // 40
const UDP_HDR_LEN: usize = 8;

/// Total stack-buffer size used by `send_to_addr`. Sized so a v6
/// frame ([14 + 40 + 8 + 1452]) fits; v4 uses fewer header bytes
/// so its payload slot is larger.
const FRAME_BUF_LEN: usize =
    executor::reactor::MAX_L2_HEADROOM + (1500 - IPV6_HDR_LEN - UDP_HDR_LEN);
// = 62 + 1452 = 1514. Same total bound for both families.

/// Fill the ETH + IP + UDP headers of `frame` in place — the UDP
/// analogue of `tcp`'s `fill_tcp_frame_headers`. `eth_off` is
/// where the Ethernet header starts; the IP and UDP headers follow
/// contiguously, and the UDP payload must already sit past them.
/// The two send paths lay the frame out at different `eth_off`s.
/// Stamps the UDP pseudo-header partial sum and the IPv4 header
/// checksum in place.
unsafe fn fill_udp_frame_headers(
    frame: &mut [u8],
    eth_off: usize,
    dst: IpAddr,
    dst_mac: MacAddr,
    src_port: u16,
    dst_port: u16,
    udp_len: usize,
) {
    // For v6 the UDP source is the unspecified `::` — no SLAAC
    // global yet; peers accept it for short-lived response traffic.
    let (ip_hdr_len, ethertype, src) = match dst {
        IpAddr::V4(_) => (
            IPV4_HDR_LEN,
            ethernet::ETHERTYPE_IPV4,
            IpAddr::V4(CONFIG.ip()),
        ),
        IpAddr::V6(_) => (
            IPV6_HDR_LEN,
            ipv6::ETHERTYPE_IPV6,
            IpAddr::V6(types::Ipv6Addr::ANY),
        ),
    };
    let ip_off = eth_off + ETH_HDR_LEN;
    let udp_off = ip_off + ip_hdr_len;

    // ── UDP header ───────────────────────────────────────────────────
    // SAFETY: `frame` holds the whole frame from `eth_off` (caller
    // sized it); `UdpHeader` is `repr(C)` POD bytes.
    let udp_hdr = unsafe { &mut *(frame.as_mut_ptr().add(udp_off) as *mut UdpHeader) };
    udp_hdr.src_port = htons(src_port);
    udp_hdr.dst_port = htons(dst_port);
    udp_hdr.length = htons(udp_len as u16);
    // Stamp the pseudo-header partial sum at the UDP checksum
    // field; the driver finishes it — device CSUM offload, or a
    // software pass when the device never negotiated it.
    udp_hdr.checksum = checksum::l4_pseudo_partial(src, dst, types::proto::UDP, udp_len);

    // ── IP header (family-dispatched) ────────────────────────────────
    let ip_total = (ip_hdr_len + udp_len) as u16;
    let ip_slot = &mut frame[ip_off..ip_off + ip_hdr_len];
    match dst {
        IpAddr::V4(d) => {
            ipv4::fill_header(ip_slot, CONFIG.ip(), d, types::proto::UDP, ip_total);
        }
        IpAddr::V6(d) => {
            ipv6::fill_header(
                ip_slot,
                &types::Ipv6Addr::ANY,
                &d,
                types::proto::UDP,
                ipv6::DEFAULT_HOP_LIMIT,
                udp_len as u16,
            );
        }
    }

    // ── Ethernet header ──────────────────────────────────────────────
    ethernet::fill_header(
        &mut frame[eth_off..eth_off + ETH_HDR_LEN],
        dst_mac,
        ethernet::ethernet_our_mac(),
        ethertype,
    );
}

/// Zero-copy UDP send. Caller pre-supplies a frame buffer where
/// the first [`executor::reactor::MAX_L2_HEADROOM`] (= 62) bytes
/// are reserved for the L2/L3/L4 headers and the UDP payload
/// starts at `frame[MAX_L2_HEADROOM..]`. Fills the headers in
/// place and ships the contiguous frame to the driver — no
/// payload memcpy.
///
/// 62 covers v6 (14 + 40 + 8). For v4 destinations the actual
/// headers are 42 bytes; we write them into the trailing 42 bytes
/// of the reserve and ship from `frame[20..]` (skipping the 20
/// unused leading bytes). Caller doesn't need to know the family.
///
/// Used by the QUIC reactor (via `UdpSocket::send_to_with_l2_
/// headroom`) to skip the per-packet UDP-wrap memcpy. ARP/NDP
/// miss drops the packet — UDP is fire-and-forget; the application
/// layer (QUIC retransmits, DNS retries) handles loss.
pub fn send_with_l2_headroom(dst: IpAddr, src_port: u16, dst_port: u16, frame: &mut [u8]) {
    use executor::reactor::MAX_L2_HEADROOM;
    debug_assert!(frame.len() >= MAX_L2_HEADROOM);

    let payload_len = frame.len() - MAX_L2_HEADROOM;
    if payload_len == 0 || payload_len > 1500 - IPV4_HDR_LEN - UDP_HDR_LEN {
        diag::COUNTERS.tx_invalid.bump();
        return;
    }
    let udp_len = UDP_HDR_LEN + payload_len;

    let dst_mac = match mac_resolve::resolve(dst) {
        Some(m) => m,
        None => {
            diag::COUNTERS.tx_mac_unresolved.bump();
            return;
        }
    };

    // The buffer reserves MAX_L2_HEADROOM (= 62, the v6 header size)
    // at the front. A v4 frame's headers are 20 B shorter, so they go
    // in the trailing bytes of the reserve and the frame ships from
    // `prefix_skip` — the leading 20 B go unused (no payload move,
    // unlike `send_via_tx_handle`).
    let ip_hdr_len = match dst {
        IpAddr::V4(_) => IPV4_HDR_LEN,
        IpAddr::V6(_) => IPV6_HDR_LEN,
    };
    let prefix_skip = MAX_L2_HEADROOM - (ETH_HDR_LEN + ip_hdr_len + UDP_HDR_LEN);

    // SAFETY: `frame` holds the headroom reserve plus the payload
    // (bounds-checked above), so the frame from `prefix_skip` on is
    // in-bounds.
    unsafe {
        fill_udp_frame_headers(
            frame,
            prefix_skip,
            dst,
            dst_mac,
            src_port,
            dst_port,
            udp_len,
        );
        let frame_slice =
            core::slice::from_raw_parts(frame.as_ptr().add(prefix_skip), frame.len() - prefix_skip);
        // The UDP checksum field holds the pseudo-header partial
        // sum; `send` hands the driver these offsets to finish it.
        // 6 = the checksum field's offset within the UDP header.
        let csum = nic::CsumOffload {
            start: (ETH_HDR_LEN + ip_hdr_len) as u16,
            offset: 6,
        };
        nic::send(frame_slice, csum);
    }
    diag::COUNTERS.tx_datagrams.bump();
}

/// Submit a `TxBufHandle` (acquired via
/// [`executor::reactor::acquire_tx_buf`]) for transmission. Caller
/// has written the UDP payload at
/// `handle.data_mut()[MAX_L2_HEADROOM..frame_len]`; we fill the
/// L2/L3/L4 headers in the headroom in place and submit the slot
/// to the driver.
///
/// For v6 destinations the wire frame uses all 62 bytes of
/// headroom (14 ETH + 40 IPv6 + 8 UDP), so the layout is
/// already correct — fill headers, submit, ship.
///
/// For v4 destinations the wire frame needs only 42 bytes of
/// header (14 + 20 + 8). To put the L2 frame at the start of
/// the slot's data field (where the driver's submit_tx assumes
/// it lives), we'd need either a 2-descriptor SG submit or an
/// in-place memmove that shifts the payload back by 20 bytes.
/// We do the memmove — same memcpy cost as the legacy
/// slice-shaped path (which also memcpy'd the payload into a
/// pool slot at submit time), so v4 doesn't regress; only v6
/// gets the full B2 win.
///
/// Bypasses the `udp::send_to_addr → drivers::net::send` chain
/// for v6 callers that build their UDP payload (e.g. the QUIC
/// encoder) directly into a TX pool slot.
/// Shared frame prep for the UDP TX-handle paths (`send_via_tx_handle`
/// and `send_udp_gso_via_tx_handle`): for v4, shift the payload back to
/// the family-correct offset so the L2 frame starts at `frame[0]`; then
/// write the Eth+IP+UDP header template (one segment's worth — the
/// device replicates it per GSO segment). `payload_len` is the total
/// UDP-payload bytes (one datagram, or the whole GSO super-payload).
/// Returns `(on_wire_len, hdr_len = Eth+IP+UDP, csum_start = Eth+IP)`.
///
/// SAFETY: `frame` must be ≥ `MAX_L2_HEADROOM + payload_len` writable
/// bytes with the payload already at `[MAX_L2_HEADROOM..]`.
unsafe fn write_udp_tx_headers(
    frame: &mut [u8],
    dst: IpAddr,
    dst_mac: MacAddr,
    src_port: u16,
    dst_port: u16,
    payload_len: usize,
) -> (usize, u16, u16) {
    use executor::reactor::MAX_L2_HEADROOM;
    let ip_hdr_len = match dst {
        IpAddr::V4(_) => IPV4_HDR_LEN,
        IpAddr::V6(_) => IPV6_HDR_LEN,
    };
    let actual_headroom = ETH_HDR_LEN + ip_hdr_len + UDP_HDR_LEN;
    unsafe {
        // v4: shift the payload back 20 B (overlapping move) so the L2
        // frame starts at frame[0], where the driver expects it.
        if matches!(dst, IpAddr::V4(_)) {
            let p = frame.as_mut_ptr();
            core::ptr::copy(p.add(MAX_L2_HEADROOM), p.add(actual_headroom), payload_len);
        }
        fill_udp_frame_headers(
            frame,
            0,
            dst,
            dst_mac,
            src_port,
            dst_port,
            UDP_HDR_LEN + payload_len,
        );
    }
    (
        actual_headroom + payload_len,
        actual_headroom as u16,
        (ETH_HDR_LEN + ip_hdr_len) as u16,
    )
}

pub fn send_via_tx_handle(
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    handle: nic_api::TxBufHandle,
    frame_len: usize,
) {
    use executor::reactor::MAX_L2_HEADROOM;
    debug_assert!(frame_len >= MAX_L2_HEADROOM);
    debug_assert!(frame_len <= handle.data_cap as usize);

    let payload_len = frame_len - MAX_L2_HEADROOM;
    if payload_len == 0 || payload_len > 1500 - IPV4_HDR_LEN - UDP_HDR_LEN {
        // Invalid input — drop. Handle's `Drop` returns the slot
        // to the pool unused.
        diag::COUNTERS.tx_invalid.bump();
        return;
    }
    let dst_mac = match mac_resolve::resolve(dst) {
        Some(m) => m,
        None => {
            // ARP/NDP miss; fire-and-forget UDP drop.
            diag::COUNTERS.tx_mac_unresolved.bump();
            return;
        }
    };
    let mut handle = handle;
    // The UDP checksum field holds the pseudo-header partial sum;
    // `submit_tx` hands the driver these offsets to finish it
    // (6 = the checksum field's offset within the UDP header).
    let (on_wire, _hdr_len, csum_start) = unsafe {
        write_udp_tx_headers(handle.data_mut(), dst, dst_mac, src_port, dst_port, payload_len)
    };
    nic::submit_tx(
        handle,
        on_wire,
        nic::CsumOffload {
            start: csum_start,
            offset: 6,
        },
    );
    diag::COUNTERS.tx_datagrams.bump();
}

/// UDP-GSO submit: the caller filled N back-to-back QUIC packets (each
/// `gso_size`, the last may be shorter) at
/// `handle.data_mut()[MAX_L2_HEADROOM..frame_len]`. We write ONE
/// Eth+IP+UDP header template in the headroom and hand the driver a
/// single segmentation descriptor; the device replicates the header per
/// `gso_size` chunk, fixing per-segment length + L4 checksum. Mirrors
/// TCP's `send_super_segment_from_cursor` (header template + zeroed L4
/// csum, device computes per segment).
pub fn send_udp_gso_via_tx_handle(
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    mut handle: nic_api::TxUdpGsoBufHandle,
    frame_len: usize,
    gso_size: u16,
) {
    use executor::reactor::MAX_L2_HEADROOM;
    debug_assert!(frame_len > MAX_L2_HEADROOM);
    debug_assert!(frame_len <= handle.data_cap() as usize);

    let payload_total = frame_len - MAX_L2_HEADROOM;
    if payload_total == 0 || gso_size == 0 {
        diag::COUNTERS.tx_invalid.bump();
        return;
    }
    let dst_mac = match mac_resolve::resolve(dst) {
        Some(m) => m,
        None => {
            diag::COUNTERS.tx_mac_unresolved.bump();
            return;
        }
    };
    // One header template (the device replicates it per gso_size
    // segment, fixing per-segment length). The v4 shift is one memmove
    // for the whole burst — amortized across N packets.
    let (on_wire, hdr_len, csum_start) = unsafe {
        write_udp_tx_headers(handle.data_mut(), dst, dst_mac, src_port, dst_port, payload_total)
    };
    // Zero the UDP checksum so the device computes a full per-segment
    // checksum (the TSO/GSO convention; the pseudo-sum the template
    // carries is moot. HVF's proxy ignores the field). csum_start is
    // the UDP-header start; +6 is the checksum field within it.
    {
        let frame = handle.data_mut();
        let udp_csum = csum_start as usize + 6;
        frame[udp_csum] = 0;
        frame[udp_csum + 1] = 0;
    }
    nic::submit_tx_udp_gso(handle, on_wire, hdr_len, csum_start, gso_size);
    diag::COUNTERS.tx_datagrams.bump();
}

/// Slice-shaped UDP send. Copies `data` into a stack-local
/// framing buffer with the headers' reserved headroom, then
/// delegates to [`send_with_l2_headroom`] for the in-place
/// header fill + driver hand-off. One payload memcpy total —
/// the legacy `udp::send_to_addr → ipv4_send → ethernet_send`
/// chain made three.
///
/// Used by `UdpSocket::send_to`, by the receive-path reply paths
/// in protocols that piggyback UDP (DNS, ICMP-port-unreachable),
/// and as the native-backend fallback for callers that opted
/// into `send_to_with_l2_headroom`.
pub fn send_to_addr(dst: IpAddr, src_port: u16, dst_port: u16, data: &[u8]) {
    use executor::reactor::MAX_L2_HEADROOM;
    if data.len() > 1500 - IPV4_HDR_LEN - UDP_HDR_LEN {
        diag::COUNTERS.tx_invalid.bump();
        return;
    }
    let mut buf = core::mem::MaybeUninit::<[u8; FRAME_BUF_LEN]>::uninit();
    let p = buf.as_mut_ptr() as *mut u8;
    unsafe {
        // Copy payload into the frame's payload slot. Headers
        // get filled in-place by `send_with_l2_headroom`.
        if !data.is_empty() {
            core::ptr::copy_nonoverlapping(data.as_ptr(), p.add(MAX_L2_HEADROOM), data.len());
        }
        let frame = core::slice::from_raw_parts_mut(p, MAX_L2_HEADROOM + data.len());
        send_with_l2_headroom(dst, src_port, dst_port, frame);
    }
}

/// Called by the network dispatch layer when protocol == UDP.
/// Delivers the datagram to the async reactor if a
/// `executor::reactor::UdpSocket` is bound to the destination port;
/// otherwise drops it.
///
/// `segment` is a borrow over driver-pool storage covering the full
/// UDP datagram (header + body). After header parse the body slice
/// is handed to `deliver_udp`, which copies it into the per-bind
/// inbox slot — synchronous w.r.t. this call, so the borrow is
/// released before we return.
pub fn udp_receive(src_ip: IpAddr, _dst_ip: IpAddr, segment: &[u8]) {
    let Some(hdr) = UdpHeader::try_ref_from(segment) else {
        diag::COUNTERS.rx_malformed.bump();
        return;
    };
    let dst_port = ntohs(hdr.dst_port);
    let src_port = ntohs(hdr.src_port);
    let udp_len = ntohs(hdr.length) as usize;
    if udp_len < 8 || udp_len > segment.len() {
        diag::COUNTERS.rx_malformed.bump();
        return;
    }
    let body = &segment[8..udp_len];
    // `deliver_udp` returns false when no socket is bound to the
    // destination port — a dropped datagram the old `let _ =`
    // discarded. Trace it, with the port, into `LAST_UNDELIVERABLE`.
    if executor::reactor::deliver_udp(dst_port, src_ip, src_port, body) {
        diag::COUNTERS.rx_datagrams.bump();
    } else {
        diag::record_undeliverable(dst_port, src_port, body.len());
    }
}
