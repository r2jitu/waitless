// net/dhcp.rs — DHCP discover/offer/request/ack.
//
// Built on top of the regular UDP stack: binds port 68 via
// `UdpSocket`, fans the per-worker reply handler out with
// `run`, and sends DISCOVER / REQUEST via `send_to` with the
// broadcast IP. The IPv4 layer's existing "`CONFIG.ip() == ANY` →
// MAC broadcast" branch handles the pre-IP corner case, so DHCP
// doesn't need a custom Ethernet/IP/UDP framer any more.
//
// This used to reach deep into the stack: a `DHCP_ACTIVE` atomic
// plus an `on_frame(&[u8])` hook let `net::net_receive` forward raw
// frames here during bring-up because we couldn't bind port 68 via
// the normal UDP path. That code is gone — everything DHCP needs
// is available to any user of `uni::runtime::UdpSocket`.

#![no_std]

extern crate arp as arp;
extern crate ethernet as ethernet;
extern crate executor;
extern crate ipv4 as ipv4;
extern crate kernel_bare;
extern crate net_from_bytes as from_bytes;
extern crate net_types as types;

mod dhcp_parse;

use arp::arp_announce;
use ethernet::ethernet_our_mac;
use executor::event::AsyncEvent;
use executor::reactor::UdpSocket;
use executor::select::timeout_us;
use from_bytes::FromBytes;
use kernel_bare::sync::Spinlock;
use types::{CONFIG, Ipv4Addr, htonl, htons};

/// Fixed DHCP/BOOTP header. 236 bytes + 4-byte magic cookie = 240
/// bytes. Options follow.
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
        // SAFETY: repr(C, packed) POD with no padding.
        unsafe {
            core::slice::from_raw_parts(
                self as *const _ as *const u8,
                core::mem::size_of::<DhcpPacket>(),
            )
        }
    }
}

// Outgoing DHCP message types. Incoming codes (`OFFER` / `ACK` /
// `NAK`) live in `dhcp_parse::MSG_*`.
const DHCP_DISCOVER: u8 = 1;
const DHCP_REQUEST: u8 = 3;

const BROADCAST_IP: types::IpAddr = types::IpAddr::V4(types::Ipv4Addr { addr: 0xFFFF_FFFF });

/// The parsed lease. `handle_reply` fills this from whichever
/// worker receives the OFFER / ACK; `discover()` reads it from
/// core 0 after the matching `AsyncEvent` fires. Completion
/// signalling lives in the events, not here — these fields are
/// pure data.
struct DhcpState {
    xid: u32,
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
            offered_ip: Ipv4Addr::ANY,
            offered_subnet: Ipv4Addr::ANY,
            offered_gateway: Ipv4Addr::ANY,
            offered_dns: Ipv4Addr::ANY,
            server_ip: Ipv4Addr::ANY,
        }
    }
}

static DHCP_STATE: Spinlock<DhcpState> = Spinlock::new(DhcpState::new());

/// Signalled by `handle_reply` when an OFFER / ACK lands (on
/// whichever worker received it); awaited by `discover()` on
/// core 0. Replaces the old `sleep_us(1 ms)` polling loop — the
/// waker fires immediately on reply, so discover() continues with
/// no extra latency and without spending CPU polling a spinlock.
static OFFER_READY: AsyncEvent = AsyncEvent::new();
static ACK_READY: AsyncEvent = AsyncEvent::new();

/// Per-datagram handler invoked from inside the `UdpSocket::run`
/// body — fires on whichever worker the OFFER / ACK arrived on.
/// Parses the DHCP payload and updates the shared `DHCP_STATE`.
/// Validation + option walking lives in `dhcp_parse`; see its
/// unit tests for the edge-case coverage.
fn handle_reply(_src_ip: types::IpAddr, src_port: u16, payload: &[u8]) {
    // DHCP servers always source from port 67. Drop anything else.
    if src_port != 67 {
        return;
    }

    let expected_xid_be = DHCP_STATE.lock().xid.to_ne_bytes();
    let yiaddr_bytes = match dhcp_parse::validate_header(payload, expected_xid_be) {
        Some(a) => a,
        None => return,
    };
    let to_addr = |o: [u8; 4]| Ipv4Addr::from(o[0], o[1], o[2], o[3]);
    let yiaddr = to_addr(yiaddr_bytes);
    let parsed = dhcp_parse::parse_options(&payload[240..]);

    let msg_type = parsed.msg_type;
    {
        let mut state = DHCP_STATE.lock();
        match msg_type {
            dhcp_parse::MSG_OFFER => {
                state.offered_ip = yiaddr;
                state.offered_subnet = parsed.subnet.map(to_addr).unwrap_or(Ipv4Addr::ANY);
                state.offered_gateway = parsed.gateway.map(to_addr).unwrap_or(Ipv4Addr::ANY);
                state.offered_dns = parsed.dns.map(to_addr).unwrap_or(Ipv4Addr::ANY);
                state.server_ip = parsed.server_id.map(to_addr).unwrap_or(Ipv4Addr::ANY);
            }
            dhcp_parse::MSG_ACK => {
                state.offered_ip = yiaddr;
                if let Some(s) = parsed.subnet {
                    state.offered_subnet = to_addr(s);
                }
                if let Some(g) = parsed.gateway {
                    state.offered_gateway = to_addr(g);
                }
                if let Some(d) = parsed.dns {
                    state.offered_dns = to_addr(d);
                }
            }
            // NAK explicitly ignored — no state update, no event
            // set. Phase 2's timeout fires and `discover()` reports
            // failure; the app then retries with Static.
            dhcp_parse::MSG_NAK => {}
            _ => {}
        }
    }
    // Wake `discover()` after releasing the lock — no deadlock on
    // the set path even if the waiter polls immediately on another
    // core. NAKs are intentionally silent: if a NAK lands during
    // Phase 2 we let the retry timeout fire and report failure.
    match msg_type {
        dhcp_parse::MSG_OFFER => OFFER_READY.set(),
        dhcp_parse::MSG_ACK => ACK_READY.set(),
        _ => {}
    }
}

/// Fill `buf` with a DHCP fixed header + the tail of the passed
/// option block, pad to BOOTP's 300-byte minimum payload, return
/// the total length written. The caller supplies the message-type +
/// any extra options as `tail`.
fn build_payload(tail: &[u8], buf: &mut [u8]) -> usize {
    let base = {
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
            flags: htons(0x8000), // broadcast flag — reply to FF:FF:FF...
            ciaddr: Ipv4Addr::ANY,
            yiaddr: Ipv4Addr::ANY,
            siaddr: Ipv4Addr::ANY,
            giaddr: Ipv4Addr::ANY,
            chaddr,
            sname: [0; 64],
            file: [0; 128],
            magic_cookie: htonl(0x63825363),
        }
    };
    buf[..240].copy_from_slice(base.as_bytes());
    buf[240..240 + tail.len()].copy_from_slice(tail);
    // BOOTP minimum: pad the whole DHCP payload to 300 bytes.
    let written = 240 + tail.len();
    written.max(300)
}

fn build_discover(buf: &mut [u8]) -> usize {
    let tail: [u8; 9] = [
        53,
        1,
        DHCP_DISCOVER,
        55,
        3,
        1,
        3,
        6, // param request list: subnet, router, DNS
        255,
    ];
    build_payload(&tail, buf)
}

fn build_request(buf: &mut [u8]) -> usize {
    let (offered_ip, server_ip) = {
        let s = DHCP_STATE.lock();
        (s.offered_ip.octets(), s.server_ip.octets())
    };
    let mut tail = [0u8; 21];
    tail[0] = 53;
    tail[1] = 1;
    tail[2] = DHCP_REQUEST;
    tail[3] = 50;
    tail[4] = 4;
    tail[5..9].copy_from_slice(&offered_ip);
    tail[9] = 54;
    tail[10] = 4;
    tail[11..15].copy_from_slice(&server_ip);
    tail[15] = 55;
    tail[16] = 3;
    tail[17] = 1;
    tail[18] = 3;
    tail[19] = 6;
    tail[20] = 255;
    build_payload(&tail, buf)
}

/// DHCP discover — awaits until IP obtained or timeout.
pub async fn discover() -> bool {
    // Bind port 68 and fan the receive loop out across every
    // worker — whichever core's RX queue the OFFER / ACK lands on
    // calls `handle_reply` there, updating `DHCP_STATE` and
    // signalling `OFFER_READY` / `ACK_READY`. Port + socket stay
    // allocated for the process lifetime (DHCP only runs once per
    // boot).
    let sock = match UdpSocket::bind(68) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // `run` returns a `UdpHandle` whose `Drop` aborts the
    // per-worker recv tasks and releases port 68 — so when
    // `discover` returns (success, timeout, or failure) the socket
    // is fully torn down. Retries of `Net::enable(Dhcp)` after a
    // transient failure can re-bind cleanly.
    let sock = sock.run(|sock| async move {
        let mut buf = [0u8; 1500];
        loop {
            let (src_ip, src_port, n) = sock.recv_from(&mut buf).await;
            handle_reply(src_ip, src_port, &buf[..n]);
        }
    });

    {
        let mut s = DHCP_STATE.lock();
        s.xid = s.xid.wrapping_add(1);
    }
    OFFER_READY.reset();
    ACK_READY.reset();

    // Phase 1: DISCOVER → OFFER
    let mut buf = [0u8; 300];
    for _ in 0..5 {
        let n = build_discover(&mut buf);
        let _ = sock.send_to(BROADCAST_IP, 67, &buf[..n]);
        if timeout_us(2_000_000, OFFER_READY.wait()).await.is_some() {
            break;
        }
    }
    if !OFFER_READY.is_set() {
        return false;
    }

    // Phase 2: REQUEST → ACK
    for _ in 0..5 {
        let n = build_request(&mut buf);
        let _ = sock.send_to(BROADCAST_IP, 67, &buf[..n]);
        if timeout_us(2_000_000, ACK_READY.wait()).await.is_some() {
            break;
        }
    }
    if !ACK_READY.is_set() {
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
            if b >= 100 {
                msg[pos] = b'0' + b / 100;
                pos += 1;
            }
            if b >= 10 {
                msg[pos] = b'0' + (b / 10) % 10;
                pos += 1;
            }
            msg[pos] = b'0' + b % 10;
            pos += 1;
            if idx < 3 {
                msg[pos] = b'.';
                pos += 1;
            }
        }
        msg[pos] = b'\n';
        pos += 1;
        kernel_bare::serial::puts(&msg[..pos]);
    }

    arp_announce();

    true
}

/// Set fallback network config (called from `bringup_static` when
/// the app opts out of DHCP, or from a failure-retry path).
pub fn set_fallback_config(
    ip_a: u8,
    ip_b: u8,
    ip_c: u8,
    ip_d: u8,
    mask_a: u8,
    mask_b: u8,
    mask_c: u8,
    mask_d: u8,
    gw_a: u8,
    gw_b: u8,
    gw_c: u8,
    gw_d: u8,
    dns_a: u8,
    dns_b: u8,
    dns_c: u8,
    dns_d: u8,
) {
    CONFIG.store(types::NetConfig {
        ip: Ipv4Addr::from(ip_a, ip_b, ip_c, ip_d),
        subnet_mask: Ipv4Addr::from(mask_a, mask_b, mask_c, mask_d),
        gateway: Ipv4Addr::from(gw_a, gw_b, gw_c, gw_d),
        dns: Ipv4Addr::from(dns_a, dns_b, dns_c, dns_d),
    });
}
