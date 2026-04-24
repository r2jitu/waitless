// net/dhcp.rs — DHCP discover/offer/request/ack.

#![no_std]

extern crate uni_kernel;
extern crate uni_drivers;
extern crate uni_runtime;
extern crate net_from_bytes as from_bytes;
extern crate net_types as types;
extern crate net_ethernet as ethernet;
extern crate net_arp as arp;
extern crate net_ipv4 as ipv4;

mod dhcp_parse;

use from_bytes::FromBytes;
use uni_kernel::sync::Spinlock;
use uni_runtime::{select::timeout_us, sleep_us};
use types::{MacAddr, Ipv4Addr, CONFIG, checksum, htons, ntohs, htonl};
use ethernet::{EthernetHeader, ethernet_our_mac, ethernet_parse, ETHERTYPE_ARP, ETHERTYPE_IPV4};
use arp::{arp_receive, arp_announce};
use ipv4::{Ipv4Header, PROTO_UDP};

#[repr(C, packed)]
struct UdpHeader {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
}

// SAFETY: repr(C, packed), all u16 fields.
unsafe impl FromBytes for UdpHeader {}

#[repr(C, packed)]
struct DhcpPacket {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    siaddr: Ipv4Addr,
    giaddr: Ipv4Addr,
    chaddr: [u8; 16],
    sname: [u8; 64],
    file: [u8; 128],
    magic_cookie: u32,
}

// SAFETY: repr(C, packed), all fields are POD integers / byte arrays / Ipv4Addr.
unsafe impl FromBytes for DhcpPacket {}

impl DhcpPacket {
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: DhcpPacket is repr(C, packed) with no padding and only
        // POD fields, so any bit pattern is a valid byte slice.
        unsafe {
            core::slice::from_raw_parts(
                self as *const _ as *const u8,
                core::mem::size_of::<DhcpPacket>(),
            )
        }
    }
}

// Outgoing DHCP message types we emit on the wire. Incoming codes
// (`OFFER` / `ACK` / `NAK`) live in `dhcp_parse::MSG_*` alongside
// the parser that consumes them.
const DHCP_DISCOVER: u8 = 1;
const DHCP_REQUEST: u8 = 3;

struct DhcpState {
    xid: u32,
    got_offer: bool,
    got_ack: bool,
    offered_ip: Ipv4Addr,
    offered_subnet: Ipv4Addr,
    offered_gateway: Ipv4Addr,
    offered_dns: Ipv4Addr,
    server_ip: Ipv4Addr,
}

impl DhcpState {
    const fn new() -> Self {
        DhcpState {
            xid: 0x12345678,
            got_offer: false,
            got_ack: false,
            offered_ip: Ipv4Addr::ANY,
            offered_subnet: Ipv4Addr::ANY,
            offered_gateway: Ipv4Addr::ANY,
            offered_dns: Ipv4Addr::ANY,
            server_ip: Ipv4Addr::ANY,
        }
    }
}

static DHCP_STATE: Spinlock<DhcpState> = Spinlock::new(DhcpState::new());

/// True while `discover()` is running. Checked by `net::net_receive`
/// to decide whether to feed the raw frame into `dhcp_receive`. We
/// can't bind port 68 via the UDP stack because DHCP runs before
/// the NetConfig is populated and `ipv4_receive` would accept
/// broadcast but the UDP port registry isn't wired in yet either.
/// Opt-in hooking during the bring-up window avoids that chicken-
/// and-egg problem cleanly.
static DHCP_ACTIVE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

pub fn is_active() -> bool {
    DHCP_ACTIVE.load(core::sync::atomic::Ordering::Acquire)
}

/// Invoked by `net::net_receive` while DHCP is active. Parses
/// DHCP/UDP/IP out of the raw frame and updates `DHCP_STATE`.
pub fn on_frame(frame: &[u8]) {
    dhcp_receive(frame);
}

/// DHCP receive callback — processes raw ethernet frames during DHCP.
///
/// Handles the eth/IP/UDP framing here; option TLV parsing and the
/// reply-header checks live in `dhcp_parse` (exhaustively unit-tested
/// standalone).
fn dhcp_receive(frame: &[u8]) {
    let (ethertype, payload) = match ethernet_parse(frame) {
        Some(v) => v,
        None => return,
    };

    if ethertype == ETHERTYPE_ARP && payload.len() >= 28 {
        arp_receive(payload);
        return;
    }

    if ethertype != ETHERTYPE_IPV4 { return; }
    let ip_hdr = match Ipv4Header::try_ref_from(payload) {
        Some(h) => h,
        None => return,
    };
    if ip_hdr.protocol != PROTO_UDP { return; }
    let ip_hdr_len = ((ip_hdr.version_ihl & 0x0F) as usize) * 4;
    if payload.len() < ip_hdr_len { return; }

    let udp = match UdpHeader::try_ref_from(&payload[ip_hdr_len..]) {
        Some(h) => h,
        None => return,
    };
    if ntohs(udp.dst_port) != 68 || ntohs(udp.src_port) != 67 { return; }

    let dhcp_offset = ip_hdr_len + 8;
    let dhcp_bytes = &payload[dhcp_offset..];

    // Header + XID + magic-cookie validation (tested in dhcp_parse).
    let expected_xid = DHCP_STATE.lock().xid;
    let expected_xid_be = expected_xid.to_ne_bytes();
    let yiaddr_bytes = match dhcp_parse::validate_header(dhcp_bytes, expected_xid_be) {
        Some(a) => a,
        None => return,
    };
    let yiaddr = Ipv4Addr::from(
        yiaddr_bytes[0], yiaddr_bytes[1], yiaddr_bytes[2], yiaddr_bytes[3],
    );

    let parsed = dhcp_parse::parse_options(&dhcp_bytes[240..]);
    let to_addr = |o: [u8; 4]| Ipv4Addr::from(o[0], o[1], o[2], o[3]);

    let mut state = DHCP_STATE.lock();
    match parsed.msg_type {
        dhcp_parse::MSG_OFFER => {
            state.offered_ip = yiaddr;
            state.offered_subnet = parsed.subnet.map(to_addr).unwrap_or(Ipv4Addr::ANY);
            state.offered_gateway = parsed.gateway.map(to_addr).unwrap_or(Ipv4Addr::ANY);
            state.offered_dns = parsed.dns.map(to_addr).unwrap_or(Ipv4Addr::ANY);
            state.server_ip = parsed.server_id.map(to_addr).unwrap_or(Ipv4Addr::ANY);
            state.got_offer = true;
        }
        dhcp_parse::MSG_ACK => {
            state.offered_ip = yiaddr;
            if let Some(s) = parsed.subnet { state.offered_subnet = to_addr(s); }
            if let Some(g) = parsed.gateway { state.offered_gateway = to_addr(g); }
            if let Some(d) = parsed.dns { state.offered_dns = to_addr(d); }
            state.got_ack = true;
        }
        dhcp_parse::MSG_NAK => {
            state.got_offer = false;
        }
        _ => {}
    }
}

fn build_dhcp_base() -> DhcpPacket {
    let mac = ethernet_our_mac();
    let mut chaddr = [0u8; 16];
    chaddr[..6].copy_from_slice(&mac.bytes);
    DhcpPacket {
        op: 1,
        htype: 1,
        hlen: 6,
        hops: 0,
        xid: DHCP_STATE.lock().xid,
        secs: 0,
        flags: htons(0x8000),
        ciaddr: Ipv4Addr::ANY,
        yiaddr: Ipv4Addr::ANY,
        siaddr: Ipv4Addr::ANY,
        giaddr: Ipv4Addr::ANY,
        chaddr,
        sname: [0; 64],
        file: [0; 128],
        magic_cookie: htonl(0x63825363),
    }
}

const DHCP_OFFSET: usize = 14 + 20 + 8;

fn dhcp_frame_prologue(frame: &mut [u8]) -> usize {
    let our_mac = ethernet_our_mac();

    let eth = unsafe { &mut *(frame.as_mut_ptr() as *mut EthernetHeader) };
    eth.dst = MacAddr::BROADCAST;
    eth.src = our_mac;
    eth.ethertype = htons(ETHERTYPE_IPV4);

    let dhcp_base = build_dhcp_base();
    frame[DHCP_OFFSET..DHCP_OFFSET + 240].copy_from_slice(dhcp_base.as_bytes());

    DHCP_OFFSET + 240
}

fn dhcp_frame_finalize(frame: &mut [u8], mut opt_pos: usize) -> usize {
    let min_dhcp_end = DHCP_OFFSET + 300;
    if opt_pos < min_dhcp_end {
        opt_pos = min_dhcp_end;
    }

    let dhcp_len = opt_pos - DHCP_OFFSET;
    let udp_len = 8 + dhcp_len;
    let ip_total = 20 + udp_len;

    let udp = unsafe { &mut *(frame.as_mut_ptr().add(14 + 20) as *mut UdpHeader) };
    udp.src_port = htons(68);
    udp.dst_port = htons(67);
    udp.length = htons(udp_len as u16);
    udp.checksum = 0;

    let ip = unsafe { &mut *(frame.as_mut_ptr().add(14) as *mut Ipv4Header) };
    ip.version_ihl = 0x45;
    ip.total_length = htons(ip_total as u16);
    ip.ttl = 64;
    ip.protocol = PROTO_UDP;
    ip.src = Ipv4Addr::ANY;
    ip.dst = Ipv4Addr::BROADCAST;
    ip.checksum = 0;
    ip.checksum = unsafe { checksum(frame.as_ptr().add(14) as *const u8, 20) };

    14 + ip_total
}

fn dhcp_send_discover() {
    let mut frame = [0u8; 590];

    let mut opt_pos = dhcp_frame_prologue(&mut frame);
    frame[opt_pos] = 53; frame[opt_pos + 1] = 1; frame[opt_pos + 2] = DHCP_DISCOVER; opt_pos += 3;
    frame[opt_pos] = 55; frame[opt_pos + 1] = 3; frame[opt_pos + 2] = 1; frame[opt_pos + 3] = 3; frame[opt_pos + 4] = 6; opt_pos += 5;
    frame[opt_pos] = 255; opt_pos += 1;

    let total = dhcp_frame_finalize(&mut frame, opt_pos);
    uni_drivers::net::send(&frame[..total]);
}

fn dhcp_send_request() {
    let mut frame = [0u8; 590];

    let mut opt_pos = dhcp_frame_prologue(&mut frame);

    let (offered_ip, server_ip) = {
        let s = DHCP_STATE.lock();
        (s.offered_ip, s.server_ip)
    };

    frame[opt_pos] = 53; frame[opt_pos + 1] = 1; frame[opt_pos + 2] = DHCP_REQUEST; opt_pos += 3;
    let ip_bytes = offered_ip.octets();
    frame[opt_pos] = 50; frame[opt_pos + 1] = 4;
    frame[opt_pos + 2..opt_pos + 6].copy_from_slice(&ip_bytes);
    opt_pos += 6;
    let srv_bytes = server_ip.octets();
    frame[opt_pos] = 54; frame[opt_pos + 1] = 4;
    frame[opt_pos + 2..opt_pos + 6].copy_from_slice(&srv_bytes);
    opt_pos += 6;
    frame[opt_pos] = 55; frame[opt_pos + 1] = 3; frame[opt_pos + 2] = 1; frame[opt_pos + 3] = 3; frame[opt_pos + 4] = 6; opt_pos += 5;
    frame[opt_pos] = 255; opt_pos += 1;

    let total = dhcp_frame_finalize(&mut frame, opt_pos);
    uni_drivers::net::send(&frame[..total]);
}

/// Wait up to `timeout_ms` for a DHCP reply. Yields to the event
/// loop every 1 ms so `net_flush_cb` kicks pending TX (DISCOVER /
/// REQUEST) and `net_poll_cb` drains RX — frames flow through
/// `net_receive → dhcp::on_frame` into `DHCP_STATE`.
async fn dhcp_await(timeout_ms: u64, wait_for_ack: bool) -> bool {
    let waiter = async {
        loop {
            let done = {
                let s = DHCP_STATE.lock();
                if wait_for_ack { s.got_ack } else { s.got_offer }
            };
            if done { return; }
            // Force a VM exit so HVF / KVM's vhost-net actually
            // injects any pending RX into the virtio ring. Without
            // this, the busy-poll-and-sleep loop here never exits
            // the guest (idle_until_cycles is a pure cycle-counter
            // wait; sleep_us is waker-driven) and the OFFER sits
            // queued host-side for the full timeout. One MMIO read
            // per ms is cheap and orders-of-magnitude simpler than
            // teaching the kernel idle path to WFI while async
            // tasks are pending.
            uni_drivers::net::poke_interrupt_status();
            sleep_us(1000).await;
        }
    };
    timeout_us(timeout_ms * 1000, waiter).await.is_some()
}

/// DHCP discover — awaits until IP obtained or timeout.
pub async fn discover() -> bool {
    {
        let mut s = DHCP_STATE.lock();
        s.got_offer = false;
        s.got_ack = false;
        s.xid = s.xid.wrapping_add(1);
    }

    DHCP_ACTIVE.store(true, core::sync::atomic::Ordering::Release);

    // Phase 1: DISCOVER → OFFER
    for _attempt in 0..5 {
        dhcp_send_discover();
        if dhcp_await(2000, false).await && DHCP_STATE.lock().got_offer {
            break;
        }
    }
    if !DHCP_STATE.lock().got_offer {
        DHCP_ACTIVE.store(false, core::sync::atomic::Ordering::Release);
        return false;
    }

    // Phase 2: REQUEST → ACK
    DHCP_STATE.lock().got_ack = false;
    for _attempt in 0..5 {
        dhcp_send_request();
        if dhcp_await(2000, true).await && DHCP_STATE.lock().got_ack {
            break;
        }
    }
    DHCP_ACTIVE.store(false, core::sync::atomic::Ordering::Release);
    if !DHCP_STATE.lock().got_ack {
        return false;
    }

    let net_config = {
        let s = DHCP_STATE.lock();
        types::NetConfig {
            ip: s.offered_ip,
            subnet_mask: s.offered_subnet,
            gateway: s.offered_gateway,
            dns: s.offered_dns,
        }
    };
    CONFIG.store(net_config);

    {
        let o = CONFIG.ip().octets();
        let mut msg = *b"dhcp: configured IP xxx.xxx.xxx.xxx\n";
        let mut pos = 20;
        for (idx, &b) in o.iter().enumerate() {
            if b >= 100 { msg[pos] = b'0' + b / 100; pos += 1; }
            if b >= 10 { msg[pos] = b'0' + (b / 10) % 10; pos += 1; }
            msg[pos] = b'0' + b % 10; pos += 1;
            if idx < 3 { msg[pos] = b'.'; pos += 1; }
        }
        msg[pos] = b'\n'; pos += 1;
        uni_kernel::serial::puts(&msg[..pos]);
    }

    arp_announce();

    true
}

/// Set fallback network config (called from entry.rs if DHCP fails).
pub fn set_fallback_config(
    ip_a: u8, ip_b: u8, ip_c: u8, ip_d: u8,
    mask_a: u8, mask_b: u8, mask_c: u8, mask_d: u8,
    gw_a: u8, gw_b: u8, gw_c: u8, gw_d: u8,
    dns_a: u8, dns_b: u8, dns_c: u8, dns_d: u8,
) {
    CONFIG.store(types::NetConfig {
        ip: Ipv4Addr::from(ip_a, ip_b, ip_c, ip_d),
        subnet_mask: Ipv4Addr::from(mask_a, mask_b, mask_c, mask_d),
        gateway: Ipv4Addr::from(gw_a, gw_b, gw_c, gw_d),
        dns: Ipv4Addr::from(dns_a, dns_b, dns_c, dns_d),
    });
}
