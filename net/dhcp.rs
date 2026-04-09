// net/dhcp.rs — DHCP discover/offer/request/ack.

#![no_std]
#![allow(static_mut_refs)]

extern crate kernel;
extern crate drivers;
extern crate net_types as types;
extern crate net_ethernet as ethernet;
extern crate net_arp as arp;
extern crate net_ipv4 as ipv4;

use core::ptr;
use types::{MacAddr, Ipv4Addr, CONFIG, checksum, htons, ntohs, htonl};
use ethernet::{EthernetHeader, ethernet_our_mac, ethernet_parse, ETHERTYPE_ARP, ETHERTYPE_IPV4};
use arp::{arp_receive, arp_announce};
use ipv4::{Ipv4Header, PROTO_UDP};
use kernel::time::udelay;

#[repr(C, packed)]
struct UdpHeader {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
}

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

const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;
const DHCP_NAK: u8 = 6;

static mut DHCP_XID: u32 = 0x12345678;
static mut DHCP_GOT_OFFER: bool = false;
static mut DHCP_GOT_ACK: bool = false;
static mut DHCP_OFFERED_IP: Ipv4Addr = Ipv4Addr::ANY;
static mut DHCP_OFFERED_SUBNET: Ipv4Addr = Ipv4Addr::ANY;
static mut DHCP_OFFERED_GATEWAY: Ipv4Addr = Ipv4Addr::ANY;
static mut DHCP_OFFERED_DNS: Ipv4Addr = Ipv4Addr::ANY;
static mut DHCP_SERVER_IP: Ipv4Addr = Ipv4Addr::ANY;

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

    if ethertype != ETHERTYPE_IPV4 || payload.len() < 20 {
        return;
    }
    let ip_hdr = unsafe { &*(payload.as_ptr() as *const Ipv4Header) };
    if ip_hdr.protocol != PROTO_UDP {
        return;
    }
    let ip_hdr_len = ((ip_hdr.version_ihl & 0x0F) as usize) * 4;
    if payload.len() < ip_hdr_len + 8 {
        return;
    }

    let udp = unsafe { &*(payload[ip_hdr_len..].as_ptr() as *const UdpHeader) };
    if ntohs(udp.dst_port) != 68 || ntohs(udp.src_port) != 67 {
        return;
    }

    let dhcp_offset = ip_hdr_len + 8;
    if payload.len() < dhcp_offset + 240 {
        return;
    }

    let dhcp = unsafe { &*(payload[dhcp_offset..].as_ptr() as *const DhcpPacket) };
    if dhcp.xid != unsafe { DHCP_XID } || dhcp.magic_cookie != htonl(0x63825363) {
        return;
    }

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

    unsafe {
        match msg_type {
            DHCP_OFFER => {
                DHCP_OFFERED_IP = dhcp.yiaddr;
                DHCP_OFFERED_SUBNET = subnet;
                DHCP_OFFERED_GATEWAY = gateway;
                DHCP_OFFERED_DNS = dns;
                DHCP_SERVER_IP = server_id;
                DHCP_GOT_OFFER = true;
            }
            DHCP_ACK => {
                DHCP_OFFERED_IP = dhcp.yiaddr;
                if subnet != Ipv4Addr::ANY { DHCP_OFFERED_SUBNET = subnet; }
                if gateway != Ipv4Addr::ANY { DHCP_OFFERED_GATEWAY = gateway; }
                if dns != Ipv4Addr::ANY { DHCP_OFFERED_DNS = dns; }
                DHCP_GOT_ACK = true;
            }
            DHCP_NAK => {
                DHCP_GOT_OFFER = false;
            }
            _ => {}
        }
    }
}

fn build_dhcp_base() -> DhcpPacket {
    let mac = ethernet_our_mac();
    let mut pkt: DhcpPacket = unsafe { core::mem::zeroed() };
    pkt.op = 1; // BOOTREQUEST
    pkt.htype = 1; // Ethernet
    pkt.hlen = 6;
    pkt.xid = unsafe { DHCP_XID };
    pkt.flags = htons(0x8000); // Broadcast
    pkt.magic_cookie = htonl(0x63825363);
    pkt.chaddr[..6].copy_from_slice(&mac.bytes);
    pkt
}

fn dhcp_send_discover() {
    // Build Ethernet + IP + UDP + DHCP frame
    let mut frame = [0u8; 590]; // 14 eth + 20 ip + 8 udp + dhcp
    let our_mac = ethernet_our_mac();

    // Ethernet header
    let eth = unsafe { &mut *(frame.as_mut_ptr() as *mut EthernetHeader) };
    eth.dst = MacAddr::BROADCAST;
    eth.src = our_mac;
    eth.ethertype = htons(ETHERTYPE_IPV4);

    // DHCP packet
    let dhcp_base = build_dhcp_base();
    let dhcp_offset = 14 + 20 + 8;
    unsafe {
        ptr::copy_nonoverlapping(
            &dhcp_base as *const _ as *const u8,
            frame.as_mut_ptr().add(dhcp_offset),
            240,
        );
    }

    // DHCP options
    let mut opt_pos = dhcp_offset + 240;
    frame[opt_pos] = 53; frame[opt_pos + 1] = 1; frame[opt_pos + 2] = DHCP_DISCOVER; opt_pos += 3;
    // Parameter request list
    frame[opt_pos] = 55; frame[opt_pos + 1] = 3; frame[opt_pos + 2] = 1; frame[opt_pos + 3] = 3; frame[opt_pos + 4] = 6; opt_pos += 5;
    frame[opt_pos] = 255; opt_pos += 1;

    // Pad DHCP payload to minimum 300 bytes (RFC 2131 / BOOTP minimum)
    let min_dhcp_end = dhcp_offset + 300;
    if opt_pos < min_dhcp_end {
        opt_pos = min_dhcp_end;
    }

    let dhcp_len = opt_pos - dhcp_offset;
    let udp_len = 8 + dhcp_len;
    let ip_total = 20 + udp_len;

    // UDP header
    let udp = unsafe { &mut *(frame.as_mut_ptr().add(14 + 20) as *mut UdpHeader) };
    udp.src_port = htons(68);
    udp.dst_port = htons(67);
    udp.length = htons(udp_len as u16);
    udp.checksum = 0;

    // IP header
    let ip = unsafe { &mut *(frame.as_mut_ptr().add(14) as *mut Ipv4Header) };
    ip.version_ihl = 0x45;
    ip.total_length = htons(ip_total as u16);
    ip.ttl = 64;
    ip.protocol = PROTO_UDP;
    ip.src = Ipv4Addr::ANY;
    ip.dst = Ipv4Addr::BROADCAST;
    ip.checksum = 0;
    ip.checksum = unsafe { checksum(frame.as_ptr().add(14) as *const u8, 20) };

    drivers::virtio_net::send(&frame[..14 + ip_total]);
}

fn dhcp_send_request() {
    let mut frame = [0u8; 590];
    let our_mac = ethernet_our_mac();

    let eth = unsafe { &mut *(frame.as_mut_ptr() as *mut EthernetHeader) };
    eth.dst = MacAddr::BROADCAST;
    eth.src = our_mac;
    eth.ethertype = htons(ETHERTYPE_IPV4);

    let dhcp_base = build_dhcp_base();
    let dhcp_offset = 14 + 20 + 8;
    unsafe {
        ptr::copy_nonoverlapping(
            &dhcp_base as *const _ as *const u8,
            frame.as_mut_ptr().add(dhcp_offset),
            240,
        );
    }

    let offered_ip = unsafe { DHCP_OFFERED_IP };
    let server_ip = unsafe { DHCP_SERVER_IP };

    // DHCP options
    let mut opt_pos = dhcp_offset + 240;
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

    // Pad DHCP payload to minimum 300 bytes (RFC 2131 / BOOTP minimum)
    let min_dhcp_end = dhcp_offset + 300;
    if opt_pos < min_dhcp_end {
        opt_pos = min_dhcp_end;
    }

    let dhcp_len = opt_pos - dhcp_offset;
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

    drivers::virtio_net::send(&frame[..14 + ip_total]);
}

fn dhcp_poll_wait(timeout_ms: u32) -> bool {
    for _ in 0..timeout_ms {
        // Poll aggressively within each ms to keep latency low
        for _ in 0..100 {
            drivers::virtio_net::poll(dhcp_receive);
            unsafe {
                if DHCP_GOT_OFFER || DHCP_GOT_ACK {
                    return true;
                }
            }
        }
        udelay(1000); // 1ms
    }
    false
}

/// DHCP discover — blocks until IP obtained or timeout.
pub fn discover() -> bool {
    unsafe {
        DHCP_GOT_OFFER = false;
        DHCP_GOT_ACK = false;
        DHCP_XID = DHCP_XID.wrapping_add(1);
    }

    // Phase 1: DISCOVER → OFFER
    for _attempt in 0..5 {
        dhcp_send_discover();
        if dhcp_poll_wait(2000) && unsafe { DHCP_GOT_OFFER } {
            break;
        }
    }
    if !unsafe { DHCP_GOT_OFFER } {
        return false;
    }

    // Phase 2: REQUEST → ACK
    unsafe { DHCP_GOT_ACK = false; }
    for _attempt in 0..5 {
        dhcp_send_request();
        if dhcp_poll_wait(2000) && unsafe { DHCP_GOT_ACK } {
            break;
        }
    }
    if !unsafe { DHCP_GOT_ACK } {
        return false;
    }

    // Apply configuration
    unsafe {
        CONFIG.store(types::NetConfig {
            ip: DHCP_OFFERED_IP,
            subnet_mask: DHCP_OFFERED_SUBNET,
            gateway: DHCP_OFFERED_GATEWAY,
            dns: DHCP_OFFERED_DNS,
        });
    }

    // Log the configured IP (bench.sh VZ path looks for this)
    {
        let o = CONFIG.ip().octets();
        let mut msg = *b"dhcp: configured IP xxx.xxx.xxx.xxx\n";
        let mut pos = 22;
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
