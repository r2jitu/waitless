// Network stack umbrella. See docs/networking.md for the Tier 1 vs
// Tier 2 dispatch design.

#![no_std]

extern crate alloc;
extern crate uni_drivers;
extern crate uni_kernel;
extern crate uni_runtime;
pub extern crate net_types as types;
pub extern crate net_ethernet as ethernet;
pub extern crate net_arp as arp;
pub extern crate net_ipv4 as ipv4;
pub extern crate net_ipv6 as ipv6;
pub extern crate net_ipv6_send as ipv6_send;
pub extern crate net_icmpv6 as icmpv6;
pub extern crate net_ndp as ndp;
pub extern crate net_tcp as tcp;
pub extern crate net_udp as udp;
pub extern crate net_dhcp as dhcp;

/// Bare-metal TCP backend vtable. Listener hooks open one TCB per
/// core; per-stream hooks use the generation-aware variants so a
/// stale handle surviving a close+reuse resolves to closed rather
/// than aliasing the new connection. `try_send` currently always
/// succeeds synchronously (bare-metal NIC TX never blocks under
/// existing load) so `TcpSend` resolves in one poll; the waker
/// plumbing is wired through anyway for forward-compatibility
/// with a future TX-backpressure implementation. `unlisten` is
/// `None` — there's no per-listener teardown on bare-metal today.
static BARE_TCP_BACKEND: uni_runtime::net::TcpBackend = uni_runtime::net::TcpBackend {
    listen: tcp_backend_listen,
    accept: tcp_backend_accept,
    unlisten: None,
    has_data: tcp::is_readable_or_closed,
    do_recv: tcp::async_recv,
    register_recv_waker: tcp::register_recv_waker,
    clear_recv_waker: tcp::clear_recv_waker,
    set_recv_buf_slot: Some(tcp::set_recv_buf_slot),
    clear_recv_buf_slot: Some(tcp::clear_recv_buf_slot),
    close: tcp::close,
    try_send: tcp::async_try_send_chain,
    register_send_waker: tcp::register_send_waker,
    clear_send_waker: tcp::clear_send_waker,
    try_send_tso: Some(tcp::try_send_tso),
    shutdown_all: Some(bare_shutdown_all),
};

/// Wrapper around `tcp::shutdown_all` that flushes the virtio-net
/// TX staging + queue-notify after the RST sweep so the host
/// observes the RSTs before `arch::shutdown()` returns. Lives here
/// (not in `net_tcp`) because that crate deliberately doesn't depend
/// on `uni_drivers`.
fn bare_shutdown_all() {
    tcp::shutdown_all();
    uni_drivers::net::flush_tx_staging();
    uni_drivers::net::flush_tx_kick_if_dirty();
}

/// Bare-metal UDP backend vtable. No `bind` / `unbind` — routing
/// is purely `UDP_REGISTRY` lookups on the NIC RX path.
static BARE_UDP_BACKEND: uni_runtime::net::UdpBackend = uni_runtime::net::UdpBackend {
    bind: None,
    unbind: None,
    send: udp::send,
    acquire_tx_buf: Some(uni_drivers::net::acquire_tx_buf),
    send_via_tx_handle: Some(udp::send_via_tx_handle),
    send_with_l2_headroom: Some(udp::send_with_l2_headroom),
};

pub fn init_stack() {
    // Per-core flag tables sized to actual core count. Must run
    // before any `poll_tier2` call dereferences them.
    let n = uni_kernel::percpu::num_cores();
    WAKEUP.init(n, |_| core::sync::atomic::AtomicBool::new(false));
    JUST_DISTRIBUTED.init(n, |_| core::sync::atomic::AtomicBool::new(false));
    arp::init();
    ipv4::init();
    init_ipv6();

    // Wire up the async `uni::runtime::TcpListener` reactor and
    // the per-stream recv/send reactors — all via a single backend
    // vtable. Listening requires one slot per core (each core
    // owns its own per-port accept pool); accept reads the
    // current core's pool and returns the first Established+
    // !accepted conn.
    uni_runtime::net::register_tcp_backend(&BARE_TCP_BACKEND);
    // UDP backend — `UdpSocket::send_to` hands datagrams to the
    // protocol stack via `udp::send`.
    uni_runtime::net::register_udp_backend(&BARE_UDP_BACKEND);
}

fn tcp_backend_listen(port: u16) -> Result<(), ()> {
    // `listen_on_core` from the BSP is safe before APs start — it
    // just CAS-claims a free slot in the target core's pool. Called
    // during `init_stack` on the BSP before `set_ready` releases
    // worker cores.
    let n = percpu::num_cores();
    for i in 0..n {
        let h = tcp::listen_on_core(i, port);
        if h.is_null() {
            return Err(());
        }
    }
    Ok(())
}

fn tcp_backend_accept(port: u16) -> uni_runtime::net::TcpStream {
    tcp::accept_on_port(port)
}

// ============================================================================
// IP-config bring-up primitives — `uni::net::Net::enable` dispatches here.
// ============================================================================

/// Returns `true` on success, `false` on DHCP timeout.
pub async fn bringup_dhcp() -> bool {
    dhcp::discover().await
}

/// `dns` is left at 0.0.0.0 — the stack doesn't resolve names.
pub fn bringup_static(
    ip: types::Ipv4Addr,
    gateway: types::Ipv4Addr,
    netmask: types::Ipv4Addr,
) {
    let ip_o = ip.octets();
    let mask_o = netmask.octets();
    let gw_o = gateway.octets();
    dhcp::set_fallback_config(
        ip_o[0], ip_o[1], ip_o[2], ip_o[3],
        mask_o[0], mask_o[1], mask_o[2], mask_o[3],
        gw_o[0], gw_o[1], gw_o[2], gw_o[3],
        0, 0, 0, 0, // DNS — unused
    );
}

use uni_kernel::percpu;

/// Whether multi-core distribution has been initialized.
static MULTICORE_INIT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Wakeup flags — set during distribution, cleared each poll cycle. The
/// distributor is single-threaded (only the lock holder writes), but
/// every core wakes up afterwards and reads the flags, so atomic load/
/// store removes the language-level data race.
static WAKEUP: uni_kernel::percpu::PerWorker<core::sync::atomic::AtomicBool> =
    uni_kernel::percpu::PerWorker::new();

/// RX poll lock: 0 = free, 1 = held. CAS-based; only one core wins
/// the right to drain the RX queue at a time.
static RX_LOCK: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Per-core "just distributed" fairness flag. Set after a core wins the
/// distributor role and releases the lock. On the next `net_poll_cb`
/// the same core checks this flag: if set, it clears it and yields the
/// cycle so another core gets first shot at the lock. If no other core
/// actually took over, this core reclaims the role naturally on the
/// cycle after (no stall: the yield is a single iteration, and we still
/// wake on the next RX interrupt).
///
/// Without this flag, the core that happens to spend more time idle
/// wins the `try_lock` CAS race consistently (because it's first to
/// try after each release), so the "rotating distributor" never
/// actually rotates under asymmetric load.
static JUST_DISTRIBUTED: uni_kernel::percpu::PerWorker<core::sync::atomic::AtomicBool> =
    uni_kernel::percpu::PerWorker::new();


/// Poll the network device and dispatch received frames through the
/// full stack: Ethernet -> ARP/IPv4 -> TCP/UDP.
///
/// In single-core mode, all processing happens here.
/// In Tier 1 multi-queue mode, each core polls its own RX queue pair
/// directly — no distributor, no RX_LOCK, no inbox.
/// In Tier 2 single-queue mode, any idle core can become the distributor
/// by acquiring the RX lock.
/// Returns true if any network work was done.
pub fn poll() -> bool {
    let num_cores = percpu::num_cores();

    if num_cores <= 1 {
        return uni_drivers::net::poll(net_receive) > 0;
    }

    // Tier 1: multi-queue — each core polls its own RX queue pair.
    if uni_drivers::net::num_queue_pairs() > 1 {
        return poll_tier1();
    }

    // Tier 2: single-queue with software distribution.
    poll_tier2(num_cores)
}

/// Tier 1 poll: each core polls its own RX queue pair directly.
/// No distributor, no RX_LOCK, no inbox.
fn poll_tier1() -> bool {
    if !MULTICORE_INIT.load(core::sync::atomic::Ordering::Relaxed) {
        MULTICORE_INIT.store(true, core::sync::atomic::Ordering::Relaxed);
        let nqp = uni_drivers::net::num_queue_pairs();
        // One write_fmt holds SERIAL_TX_LOCK for the whole line so a
        // concurrent klog! on another core can't slip in mid-message.
        uni_kernel::serial::write_fmt(format_args!(
            "[net] Tier 1: per-core RX queues ({} queue pairs)\n", nqp
        ));
    }
    let core = uni_kernel::cpu_id();
    let nqp = uni_drivers::net::num_queue_pairs() as u32;
    // Pre-`set_ready` (boot-task window): only the BSP is polling;
    // APs are still idling at the top of `eventloop::run`. If a
    // multi-queue NIC hashes inbound traffic to a queue >0 (e.g.
    // vhost-net routes a DHCP OFFER to queue 1 by 4-tuple hash),
    // no AP is draining it and DHCP retries time out. While in
    // that window the BSP polls every queue. Once `set_ready` has
    // fired we fall back to the per-core scheme — APs are then
    // polling their own queues, and double-polling would race on
    // the per-queue cursor atomics.
    if core == 0 && !uni_kernel::eventloop::is_ready() {
        let mut total = 0;
        for q in 0..nqp as usize {
            total += uni_drivers::net::poll_qp(q, net_receive);
        }
        return total > 0;
    }
    // Only cores with `core < nqp` poll RX — two cores hammering the
    // same queue race on the cursor atomics and double-deliver /
    // miss packets. Cores beyond nqp still do service work (they
    // run handlers for connections whose RX landed on a polling
    // core); they just don't drive the NIC directly.
    if core >= nqp {
        return false;
    }
    let count = uni_drivers::net::poll_qp(core as usize, net_receive);
    count > 0
}

fn poll_tier2(num_cores: u32) -> bool {
    if !MULTICORE_INIT.load(core::sync::atomic::Ordering::Relaxed) {
        MULTICORE_INIT.store(true, core::sync::atomic::Ordering::Relaxed);
        uni_kernel::serial::write_fmt(format_args!(
            "[net] Tier 2: software distribution ({} cores)\n", num_cores
        ));
    }

    let my_core = uni_kernel::cpu_id();

    // Cooperative yield for fair rotation: if we just distributed on the
    // previous cycle, skip this attempt so another (presumably busier)
    // core has first shot at the lock. We still wake on the next RX
    // interrupt and will reclaim the role on the cycle after if no one
    // else takes over.
    if num_cores > 1
        && JUST_DISTRIBUTED.at(my_core)
            .swap(false, core::sync::atomic::Ordering::Relaxed)
    {
        return false;
    }

    // Try to become the distributor.
    let got_lock = RX_LOCK
        .compare_exchange(
            0, 1,
            core::sync::atomic::Ordering::Acquire,
            core::sync::atomic::Ordering::Relaxed,
        )
        .is_ok();
    if !got_lock {
        return false;
    }

    // Flush TX staging first — responses from previous cycle.
    uni_drivers::net::flush_tx_staging();

    // Poll VirtIO RX and distribute directly (no batch buffer copy).
    for i in 0..num_cores {
        WAKEUP.at(i).store(false, core::sync::atomic::Ordering::Relaxed);
    }

    let count = uni_drivers::net::poll(distribute_frame);

    // Mark ourselves as "just distributed" — our next poll attempt will
    // yield, giving other cores first shot at the lock.
    if num_cores > 1 {
        JUST_DISTRIBUTED.at(my_core)
            .store(true, core::sync::atomic::Ordering::Relaxed);
    }

    // Release lock.
    RX_LOCK.store(0, core::sync::atomic::Ordering::Release);

    let had_frames = count > 0;
    if had_frames {
        // Wake only the specific cores that received inbox data.
        // Broadcast wake_cores() is expensive on HVF: each SGI causes
        // a WFI wake (~5µs) on every core, even if it has no work.
        for i in 1..num_cores {
            if WAKEUP.at(i).load(core::sync::atomic::Ordering::Relaxed) {
                #[cfg(target_arch = "aarch64")]
                uni_kernel::aarch64::smp::send_sgi_to(i);
                #[cfg(target_arch = "x86_64")]
                uni_kernel::send_ipi(i);
            }
        }
    }

    // Flush TX (APs may have responded during distribution).
    uni_drivers::net::flush_tx_staging();

    had_frames
}


/// Process a single received frame through the full stack inline
/// (no cross-core distribution). Called from the Tier 1 per-core
/// poll, the single-core fallback, and `net_drain_cb` (after the
/// Tier 2 distributor copied frame bytes into this core's inbox).
///
/// `frame` is a borrow over driver-pool storage (Tier 1) or the
/// owning core's inbox slot (Tier 2). It is only valid for this
/// call.
///
/// Bridge: `tcp::tcp_receive` / `udp::udp_receive` still take owned
/// `IOBuf`, so we heap-wrap the L4 segment. That regresses RX to
/// the pre-88a3ccd wrap-alloc shape (one heap alloc per packet) —
/// the follow-up commit changes the L4 entries to `&[u8]` and adds
/// per-conn ring buffers, restoring (and beating) the previous
/// allocs/iter profile.
pub fn net_receive(frame: &[u8]) {
    let Some((src_mac, ethertype, payload)) = ethernet::ethernet_parse_full(frame) else {
        return;
    };
    match ethertype {
        ethernet::ETHERTYPE_ARP => {
            arp::arp_receive(payload);
        }
        ethernet::ETHERTYPE_IPV4 => {
            let Some(pkt) = ipv4::ipv4_receive(payload) else { return };
            if ipv4::same_subnet(pkt.src) {
                arp::arp_learn(pkt.src, src_mac);
            }
            let proto = pkt.protocol;
            let src = types::IpAddr::V4(types::Ipv4Addr { addr: pkt.src.addr });
            let dst = types::IpAddr::V4(types::Ipv4Addr { addr: pkt.dst.addr });
            match proto {
                ipv4::PROTO_UDP => udp::udp_receive(src, dst, pkt.payload),
                ipv4::PROTO_TCP => tcp::tcp_receive(src, dst, pkt.payload),
                _ => {}
            }
        }
        ipv6::ETHERTYPE_IPV6 => {
            ipv6_receive_frame(frame, src_mac);
        }
        _ => {}
    }
}

/// Tier 2 distributor decision — classify an IOBuf for distribution.
/// Returns where the frame should go: inline on the polling core,
/// distributed to a peer core, or dropped. Side effect: ARP-learns
/// from on-subnet IPv4 senders so the polling core's ARP cache
/// stays warm regardless of where the packet ends up handled.
fn classify_for_distribution(
    frame: &[u8],
    num_cores: u32,
    my_core: u32,
) -> ClassifyResult {
    let Some((src_mac, ethertype, payload)) = ethernet::ethernet_parse_full(frame) else {
        return ClassifyResult::Drop;
    };
    match ethertype {
        ethernet::ETHERTYPE_ARP | ipv6::ETHERTYPE_IPV6 => ClassifyResult::Inline,
        ethernet::ETHERTYPE_IPV4 => {
            let Some(pkt) = ipv4::ipv4_receive(payload) else {
                return ClassifyResult::Drop;
            };
            if ipv4::same_subnet(pkt.src) {
                arp::arp_learn(pkt.src, src_mac);
            }
            let (src_port, dst_port) = if pkt.payload.len() >= 4 {
                (u16::from_be_bytes([pkt.payload[0], pkt.payload[1]]),
                 u16::from_be_bytes([pkt.payload[2], pkt.payload[3]]))
            } else {
                (0, 0)
            };
            let target = flow_hash(
                pkt.src.addr, pkt.dst.addr, src_port, dst_port, num_cores,
            );
            if target == my_core || num_cores <= 1 {
                ClassifyResult::Inline
            } else {
                ClassifyResult::Distribute(target)
            }
        }
        _ => ClassifyResult::Drop,
    }
}

enum ClassifyResult {
    /// Hand off to `net_receive` on this core (ARP, IPv6,
    /// or IPv4 destined for `my_core`).
    Inline,
    /// Copy frame bytes to target core's `rx_inbox`; target wakes
    /// up and consumes via `net_drain_cb`.
    Distribute(u32),
    /// Frame is unparseable / wrong ethertype.
    Drop,
}

/// Tier 2 distributor. Picks a target core for the frame; runs the
/// full receive path inline for ARP / IPv6 / my-core IPv4, or
/// copies the bytes into the target core's `rx_inbox` for other
/// IPv4. The copy at the cross-core boundary is unavoidable — the
/// driver re-arms its buffer as soon as this fn returns, so we
/// can't keep a borrow over it.
fn distribute_frame(frame: &[u8]) {
    let num_cores = percpu::num_cores();
    let my_core = uni_kernel::cpu_id();
    match classify_for_distribution(frame, num_cores, my_core) {
        ClassifyResult::Inline => net_receive(frame),
        ClassifyResult::Distribute(target) => {
            // SAFETY: `percpu::init()` runs before any AP starts;
            // target is bounded by `num_cores`.
            let core = unsafe { percpu::get(target) };
            if core.rx_inbox.push(frame) {
                WAKEUP.at(target).store(true, core::sync::atomic::Ordering::Relaxed);
            }
            // push returning false (oversize / ring full) drops the
            // frame; TCP retransmit / UDP application retry recover.
        }
        ClassifyResult::Drop => {}
    }
}

// ============================================================================
// IPv6 receive + ICMPv6 / NDP service
// ============================================================================

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// Our link-local IPv6 address, derived from the NIC MAC at
/// `init_ipv6` time via modified EUI-64 (RFC 4291). Stored as 16
/// `AtomicU8`s so a multi-core read-during-init never races.
/// Single writer (BSP at boot); many readers (per-core RX paths).
static IPV6_LL_OCTETS: [AtomicU8; 16] = [
    AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
    AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
    AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
    AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
];
static IPV6_INITIALIZED: AtomicBool = AtomicBool::new(false);

fn ipv6_ll() -> types::Ipv6Addr {
    let mut o = [0u8; 16];
    for (i, slot) in IPV6_LL_OCTETS.iter().enumerate() {
        o[i] = slot.load(Ordering::Acquire);
    }
    types::Ipv6Addr { octets: o }
}

/// Our SLAAC-assigned global IPv6 address. Populated when a Router
/// Advertisement carrying a Prefix Information option (autonomous
/// flag set) arrives. Same atomic-array shape as the link-local
/// for race-free per-core reads.
static IPV6_GLOBAL_OCTETS: [AtomicU8; 16] = [
    AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
    AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
    AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
    AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
];
static IPV6_GLOBAL_SET: AtomicBool = AtomicBool::new(false);

fn ipv6_global() -> Option<types::Ipv6Addr> {
    if !IPV6_GLOBAL_SET.load(Ordering::Acquire) {
        return None;
    }
    let mut o = [0u8; 16];
    for (i, slot) in IPV6_GLOBAL_OCTETS.iter().enumerate() {
        o[i] = slot.load(Ordering::Acquire);
    }
    Some(types::Ipv6Addr { octets: o })
}

/// Initialise our IPv6 link-local address from the cached MAC. Idempotent;
/// the BSP calls this once after `ethernet::init_mac`.
pub fn init_ipv6() {
    if IPV6_INITIALIZED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let mac = ethernet::ethernet_our_mac();
    let ll = types::Ipv6Addr::link_local_from_mac(&mac);
    for (i, slot) in IPV6_LL_OCTETS.iter().enumerate() {
        slot.store(ll.octets[i], Ordering::Release);
    }
    uni_kernel::serial::write_fmt(format_args!(
        "[net] ipv6 link-local fe80::{:x}:{:x}:{:x}:{:x}\n",
        u16::from_be_bytes([ll.octets[8], ll.octets[9]]),
        u16::from_be_bytes([ll.octets[10], ll.octets[11]]),
        u16::from_be_bytes([ll.octets[12], ll.octets[13]]),
        u16::from_be_bytes([ll.octets[14], ll.octets[15]]),
    ));
    // Send Router Solicitation to ff02::2 to ask any on-link
    // router to advertise its prefix. RFC 4861 §6.3.7: hosts
    // SHOULD send RS at startup to avoid waiting up to 200 s for
    // an unsolicited RA. Multicast destination → MAC is the
    // deterministic 33:33:00:00:00:02 so we don't need NDP.
    send_router_solicitation();
}

fn send_router_solicitation() {
    let mac = ethernet::ethernet_our_mac();
    let ll = ipv6_ll();
    let dst = types::Ipv6Addr::ALL_ROUTERS_LL;
    let mut icmp = [0u8; 32];
    let n = match icmpv6::build_router_solicitation(&ll, &dst, &mac, &mut icmp) {
        Some(n) => n,
        None => return,
    };
    // Multicast destination → ipv6_send picks the
    // 33:33:00:00:00:02 mapping internally.
    ipv6_send::ipv6_send(
        &ll,
        &dst,
        ipv6::next_header::ICMPV6,
        255,
        &icmp[..n],
    );
}

/// Process an inbound Router Advertisement. If it carries a
/// Prefix Information option with the autonomous flag set, derive
/// our global address by combining the prefix with the modified
/// EUI-64 interface ID and stash it. The first such RA wins;
/// later RAs with different prefixes are ignored (single-prefix
/// MVP — adding multi-prefix support is a future expansion).
fn handle_router_advertisement(payload: &[u8]) {
    let ra = match icmpv6::parse_router_advertisement(payload) {
        Ok(r) => r,
        Err(_) => return,
    };
    let pfx = match icmpv6::find_prefix_info(ra.options) {
        Some(p) => p,
        None => return,
    };
    if !pfx.autonomous || pfx.prefix_length != 64 {
        // §5.5.3: SLAAC only when A=1 and prefix length is 64
        // (the EUI-64 interface ID is exactly 64 bits).
        return;
    }
    if IPV6_GLOBAL_SET.swap(true, Ordering::AcqRel) {
        return; // already configured
    }
    let mac = ethernet::ethernet_our_mac();
    let ll = types::Ipv6Addr::link_local_from_mac(&mac);
    // Combine: high 64 bits from prefix, low 64 bits from
    // link-local's EUI-64 interface ID.
    let mut o = [0u8; 16];
    o[..8].copy_from_slice(&pfx.prefix.octets[..8]);
    o[8..].copy_from_slice(&ll.octets[8..]);
    for (i, slot) in IPV6_GLOBAL_OCTETS.iter().enumerate() {
        slot.store(o[i], Ordering::Release);
    }
    uni_kernel::serial::write_fmt(format_args!(
        "[net] ipv6 SLAAC: configured {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}::{:x}:{:x}:{:x}:{:x}\n",
        o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7],
        u16::from_be_bytes([o[8], o[9]]),
        u16::from_be_bytes([o[10], o[11]]),
        u16::from_be_bytes([o[12], o[13]]),
        u16::from_be_bytes([o[14], o[15]]),
    ));
}

/// Fill `out` with the addresses we accept inbound IPv6 packets
/// to: link-local, its solicited-node multicast, all-nodes
/// link-local (ff02::1), and the SLAAC global (when configured)
/// + its solicited-node group. Returns the number of slots used.
fn our_v6_addrs(out: &mut [types::Ipv6Addr; 5]) -> usize {
    let ll = ipv6_ll();
    out[0] = ll;
    out[1] = types::Ipv6Addr::solicited_node(&ll);
    out[2] = types::Ipv6Addr::ALL_NODES_LL;
    let mut n = 3;
    if let Some(g) = ipv6_global() {
        out[n] = g;
        out[n + 1] = types::Ipv6Addr::solicited_node(&g);
        n += 2;
    }
    n
}

fn ipv6_receive_frame(frame: &[u8], src_mac: types::MacAddr) {
    let Some((_, _, eth_payload)) = ethernet::ethernet_parse_full(frame) else {
        return;
    };
    let mut addr_buf = [types::Ipv6Addr::ANY; 5];
    let n = our_v6_addrs(&mut addr_buf);
    let pkt = match ipv6::ipv6_receive(eth_payload, &addr_buf[..n]) {
        Some(p) => p,
        None => return,
    };
    // Snoop (peer_v6, peer_mac) into the NDP cache so future
    // server-initiated outbound to this peer doesn't need an active
    // Neighbor Solicitation. Mirrors the IPv4 ARP-snoop pattern.
    ndp::ndp_learn(pkt.src, src_mac);
    match pkt.next_header {
        ipv6::next_header::ICMPV6 => {
            handle_icmpv6(&pkt, src_mac);
        }
        proto @ (ipv6::next_header::TCP | ipv6::next_header::UDP) => {
            let src = types::IpAddr::V6(pkt.src);
            let dst = types::IpAddr::V6(pkt.dst);
            if proto == ipv6::next_header::TCP {
                tcp::tcp_receive(src, dst, pkt.payload);
            } else {
                udp::udp_receive(src, dst, pkt.payload);
            }
        }
        _ => {}
    }
}

fn handle_icmpv6(pkt: &ipv6::Ipv6Packet<'_>, src_mac: types::MacAddr) {
    if pkt.payload.is_empty() {
        return;
    }
    if icmpv6::verify_checksum(&pkt.src, &pkt.dst, pkt.payload).is_err() {
        return;
    }
    match pkt.payload[0] {
        icmpv6::msg::ECHO_REQUEST => {
            // Reply: src = our LL, dst = original src. RFC 4443 §4.2:
            // hop limit 64 (default).
            let mut icmp_out = [0u8; 1500 - ipv6::HEADER_LEN];
            let n = match icmpv6::build_echo_reply(&ipv6_ll(), &pkt.src, pkt.payload, &mut icmp_out) {
                Some(n) => n,
                None => return,
            };
            ipv6_send::ipv6_send_to_mac(
                &ipv6_ll(),
                &pkt.src,
                src_mac,
                ipv6::next_header::ICMPV6,
                64,
                &icmp_out[..n],
            );
        }
        icmpv6::msg::ROUTER_ADVERTISEMENT => {
            handle_router_advertisement(pkt.payload);
        }
        icmpv6::msg::NEIGHBOR_SOLICITATION => {
            let ns = match icmpv6::parse_neighbor_solicitation(pkt.payload) {
                Ok(ns) => ns,
                Err(_) => return,
            };
            // Respond if the target is one of our addresses
            // (link-local OR the SLAAC global).
            let is_ours = ns.target == ipv6_ll()
                || ipv6_global().map_or(false, |g| g == ns.target);
            if !is_ours {
                return;
            }
            let mac = ethernet::ethernet_our_mac();
            // src of the NA echoes the target the peer asked
            // about so they can match it against their NS state.
            let na_src = ns.target;
            let mut icmp_out = [0u8; 64];
            let n = match icmpv6::build_neighbor_advertisement(
                &na_src,
                &pkt.src,
                &ns.target,
                &mac,
                &mut icmp_out,
            ) {
                Some(n) => n,
                None => return,
            };
            // Send the NA back to the soliciting host. Prefer the
            // SLLA option's MAC if present, falling back to the
            // inbound frame's source MAC.
            let dst_mac = ns.src_lla.unwrap_or(src_mac);
            ipv6_send::ipv6_send_to_mac(
                &na_src,
                &pkt.src,
                dst_mac,
                ipv6::next_header::ICMPV6,
                255,
                &icmp_out[..n],
            );
        }
        _ => {}
    }
}


/// Flow hash: map a 4-tuple to a core index for Tier 2 distribution.
///
/// Tier 2 uses a rotating distributor: any idle core can try_lock the
/// RX_LOCK and become the distributor for one poll cycle. Flows are
/// hashed across all cores, and the current distributor processes its
/// own flows inline while pushing other cores' flows to their inbox.
///
/// Uses FNV-1a over the 4-tuple followed by a Murmur3 fmix32 so that
/// `% num_cores` is uniform even when inputs vary in only one field
/// (e.g. wrk opens N connections from the same src IP to the same
/// dst port — without the finalizer all flows collapse to a single
/// core on `num_cores = 2`, which was masking the multi-core path).
fn flow_hash(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, num_cores: u32) -> u32 {
    let mut h: u32 = 2166136261; // FNV offset basis
    h ^= src_ip;
    h = h.wrapping_mul(16777619);
    h ^= dst_ip;
    h = h.wrapping_mul(16777619);
    h ^= src_port as u32;
    h = h.wrapping_mul(16777619);
    h ^= dst_port as u32;
    h = h.wrapping_mul(16777619);
    // Murmur3 fmix32 — make low bits depend uniformly on the whole input.
    h ^= h >> 16;
    h = h.wrapping_mul(0x85ebca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2ae35);
    h ^= h >> 16;
    h % num_cores
}

// ============================================================================
// Event loop integration
// ============================================================================

/// Register network callbacks with the kernel event loop.
/// Called during boot after virtio-net is initialized.
pub fn init_eventloop() {
    uni_kernel::eventloop::set_net_poll(net_poll_cb);
    uni_kernel::eventloop::set_net_drain(net_drain_cb);
    uni_kernel::eventloop::set_net_flush(net_flush_cb);
    // NAPI re-arm: right before the event loop HLTs, re-enable RX
    // notifications on this core's queue pair and re-check the ring.
    uni_kernel::eventloop::set_net_rearm_rx(uni_drivers::net::rearm_rx_napi);
    // Batch TX kicks: defer MMIO writes until `net_flush_cb` fires at
    // the end of each event-loop tick. Correct for the whole boot
    // because DHCP now runs as an async task polled by the event loop
    // — so the flush hook fires between DISCOVER/REQUEST sends and
    // the next `dhcp_await` poll.
    uni_drivers::net::enable_deferred_tx_kick();
}

fn net_poll_cb(_core_id: u32) -> bool {
    // Tier 1 (multi-queue): every core polls its own queue — no lock.
    if uni_drivers::net::num_queue_pairs() > 1 {
        return poll();
    }
    // Tier 2: any core can become the rotating distributor; the RX_LOCK CAS
    // in poll_tier2 picks one winner per cycle.
    if RX_LOCK.load(core::sync::atomic::Ordering::Relaxed) != 0 {
        return false;
    }
    poll()
}

fn net_drain_cb(core_id: u32) -> bool {
    // SAFETY: the kernel event loop only calls this callback with the
    // current core's id; we threaded that id through, so it matches
    // `cpu_id()` at this exact moment without needing a second TLS read.
    let cc = unsafe { percpu::CurrentWorker::from_id_unchecked(core_id) };
    let core = percpu::percore(&cc);
    let mut did_work = false;
    // Tier 2 cross-core delivery: distributor copied frame bytes
    // into our inbox; pop each slot and dispatch inline.
    while core.rx_inbox.pop_with(|frame| net_receive(frame)) {
        did_work = true;
    }
    did_work
}

fn net_flush_cb() {
    let nqp = uni_drivers::net::num_queue_pairs();
    if nqp > 1 {
        // Tier 1: each core flushes its own TX queue pair. No staging needed.
        uni_drivers::net::flush_tx_kick_if_dirty();
    } else {
        uni_drivers::net::flush_tx_staging();
        // Only kick if new TX buffers were actually added. Skipping
        // redundant kicks saves ~7 MMIO exits/request at high concurrency.
        uni_drivers::net::flush_tx_kick_if_dirty();
    }
}

