// net/dhcp.rs — DHCP discover/offer/request/ack.

#![no_std]

extern crate kernel;
extern crate drivers;
extern crate net_from_bytes as from_bytes;
extern crate net_types as types;
extern crate net_ethernet as ethernet;
extern crate net_arp as arp;
extern crate net_ipv4 as ipv4;

use from_bytes::FromBytes;
use kernel::sync::Spinlock;
use kernel::time::udelay;
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
    /// View this packet as a `&[u8]` of exactly its 240-byte wire size.
    /// Safe because `DhcpPacket` is `repr(C, packed)` POD.
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

const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;
const DHCP_NAK: u8 = 6;

/// DHCP negotiation state. The negotiation runs once at boot but
/// `dhcp_receive` is invoked from the network stack callback (which
/// could in principle run on any core), so the state lives behind a
/// spinlock to avoid the cross-core race.
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

/// DHCP receive callback — processes raw ethernet frames during DHCP.
fn dhcp_receive(frame: &[u8]) {
    let (ethertype, payload) = match ethernet_parse(frame) {
        Some(v) => v,
        None => return,
    };

    // Also process ARP during DHCP
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
    if payload.len() < dhcp_offset { return; }
    let dhcp = match DhcpPacket::try_ref_from(&payload[dhcp_offset..]) {
        Some(h) => h,
        None => return,
    };
    let xid = dhcp.xid;
    let cookie = dhcp.magic_cookie;
    if xid != DHCP_STATE.lock().xid || cookie != htonl(0x63825363) { return; }

    // Parse options
    let opts_start = dhcp_offset + 240;
    let opts_data = &payload[opts_start..];

    let mut msg_type: u8 = 0;
    let mut subnet = Ipv4Addr::ANY;
    let mut gateway = Ipv4Addr::ANY;
    let mut dns = Ipv4Addr::ANY;
    let mut server_id = Ipv4Addr::ANY;

    let mut i = 0;
    while i < opts_data.len() {
        let opt = opts_data[i];
        if opt == 255 { break; } // End
        if opt == 0 { i += 1; continue; } // Pad
        if i + 1 >= opts_data.len() { break; }
        let opt_len = opts_data[i + 1] as usize;
        if i + 2 + opt_len > opts_data.len() { break; }
        let val = &opts_data[i + 2..i + 2 + opt_len];

        match opt {
            1 if val.len() >= 4 => subnet = Ipv4Addr::from(val[0], val[1], val[2], val[3]),
            3 if val.len() >= 4 => gateway = Ipv4Addr::from(val[0], val[1], val[2], val[3]),
            6 if val.len() >= 4 => dns = Ipv4Addr::from(val[0], val[1], val[2], val[3]),
            53 if val.len() >= 1 => msg_type = val[0],
            54 if val.len() >= 4 => server_id = Ipv4Addr::from(val[0], val[1], val[2], val[3]),
            _ => {}
        }

        i += 2 + opt_len;
    }

    let yiaddr = dhcp.yiaddr;
    let mut state = DHCP_STATE.lock();
    match msg_type {
        DHCP_OFFER => {
            state.offered_ip = yiaddr;
            state.offered_subnet = subnet;
            state.offered_gateway = gateway;
            state.offered_dns = dns;
            state.server_ip = server_id;
            state.got_offer = true;
        }
        DHCP_ACK => {
            state.offered_ip = yiaddr;
            if subnet != Ipv4Addr::ANY { state.offered_subnet = subnet; }
            if gateway != Ipv4Addr::ANY { state.offered_gateway = gateway; }
            if dns != Ipv4Addr::ANY { state.offered_dns = dns; }
            state.got_ack = true;
        }
        DHCP_NAK => {
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
        op: 1,    // BOOTREQUEST
        htype: 1, // Ethernet
        hlen: 6,
        hops: 0,
        xid: DHCP_STATE.lock().xid,
        secs: 0,
        flags: htons(0x8000), // Broadcast
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

/// Build the Ethernet/IP/UDP/DHCP-base prologue into `frame` and return the
/// option-write position (start of DHCP options).
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

/// Pad to BOOTP minimum, fill in UDP/IP headers + checksum, and return the
/// total wire length to send.
fn dhcp_frame_finalize(frame: &mut [u8], mut opt_pos: usize) -> usize {
    // Pad DHCP payload to minimum 300 bytes (RFC 2131 / BOOTP minimum)
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
    let mut frame = [0u8; 590]; // 14 eth + 20 ip + 8 udp + dhcp

    let mut opt_pos = dhcp_frame_prologue(&mut frame);
    frame[opt_pos] = 53; frame[opt_pos + 1] = 1; frame[opt_pos + 2] = DHCP_DISCOVER; opt_pos += 3;
    // Parameter request list
    frame[opt_pos] = 55; frame[opt_pos + 1] = 3; frame[opt_pos + 2] = 1; frame[opt_pos + 3] = 3; frame[opt_pos + 4] = 6; opt_pos += 5;
    frame[opt_pos] = 255; opt_pos += 1;

    let total = dhcp_frame_finalize(&mut frame, opt_pos);
    drivers::virtio_net::send(&frame[..total]);
}

fn dhcp_send_request() {
    let mut frame = [0u8; 590];

    let mut opt_pos = dhcp_frame_prologue(&mut frame);

    let (offered_ip, server_ip) = {
        let s = DHCP_STATE.lock();
        (s.offered_ip, s.server_ip)
    };

    frame[opt_pos] = 53; frame[opt_pos + 1] = 1; frame[opt_pos + 2] = DHCP_REQUEST; opt_pos += 3;
    // Requested IP
    let ip_bytes = offered_ip.octets();
    frame[opt_pos] = 50; frame[opt_pos + 1] = 4;
    frame[opt_pos + 2..opt_pos + 6].copy_from_slice(&ip_bytes);
    opt_pos += 6;
    // Server ID
    let srv_bytes = server_ip.octets();
    frame[opt_pos] = 54; frame[opt_pos + 1] = 4;
    frame[opt_pos + 2..opt_pos + 6].copy_from_slice(&srv_bytes);
    opt_pos += 6;
    // Parameter request list
    frame[opt_pos] = 55; frame[opt_pos + 1] = 3; frame[opt_pos + 2] = 1; frame[opt_pos + 3] = 3; frame[opt_pos + 4] = 6; opt_pos += 5;
    frame[opt_pos] = 255; opt_pos += 1;

    let total = dhcp_frame_finalize(&mut frame, opt_pos);
    drivers::virtio_net::send(&frame[..total]);
}

fn dhcp_poll_wait(timeout_ms: u32, wait_for_ack: bool) -> bool {
    for _ in 0..timeout_ms {
        // Poll aggressively within each ms to keep latency low.
        // The poke_interrupt_status() call reads the virtio MMIO
        // INTERRUPT_STATUS register, which forces a VM exit on HVF
        // and lets the host inject any pending RX frames before
        // we check the used ring. Without this, the tight poll
        // loop never triggers an MMIO exit and the host can't
        // deliver DHCP replies during the timeout window.
        drivers::virtio_net::poke_interrupt_status();
        for _ in 0..100 {
            drivers::virtio_net::poll(dhcp_receive);
            let s = DHCP_STATE.lock();
            if wait_for_ack {
                if s.got_ack { return true; }
            } else {
                if s.got_offer { return true; }
            }
        }
        udelay(1000); // 1ms
    }
    false
}

/// DHCP discover — blocks until IP obtained or timeout.
pub fn discover() -> bool {
    {
        let mut s = DHCP_STATE.lock();
        s.got_offer = false;
        s.got_ack = false;
        s.xid = s.xid.wrapping_add(1);
    }

    // Phase 1: DISCOVER → OFFER
    for _attempt in 0..5 {
        dhcp_send_discover();
        if dhcp_poll_wait(2000, false) && DHCP_STATE.lock().got_offer {
            break;
        }
    }
    if !DHCP_STATE.lock().got_offer {
        return false;
    }

    // Phase 2: REQUEST → ACK
    DHCP_STATE.lock().got_ack = false;
    for _attempt in 0..5 {
        dhcp_send_request();
        if dhcp_poll_wait(2000, true) && DHCP_STATE.lock().got_ack {
            break;
        }
    }
    if !DHCP_STATE.lock().got_ack {
        return false;
    }

    // Apply configuration
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

    // Log the configured IP (bench.sh VZ path looks for this)
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
        kernel::serial::puts(&msg[..pos]);
    }

    // Gratuitous ARP
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
