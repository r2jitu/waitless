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
pub extern crate net_tcp as tcp;
pub extern crate net_udp as udp;
pub extern crate net_dhcp as dhcp;
pub extern crate net_protocol as protocol;

pub static REGISTRY: protocol::Registry = protocol::Registry::new();

// Adapters converting the u32-IP registry ABI to the Ipv4Addr-typed
// `*_receive` entry points. Here rather than inside each protocol
// crate so `net_protocol` stays dep-free (its rust_test would
// otherwise inherit `:types`' panic-strategy conflict).
fn tcp_dispatch(src: u32, dst: u32, payload: &[u8]) {
    tcp::tcp_receive(
        types::Ipv4Addr { addr: src },
        types::Ipv4Addr { addr: dst },
        payload,
    );
}
fn udp_dispatch(src: u32, dst: u32, payload: &[u8]) {
    udp::udp_receive(
        types::Ipv4Addr { addr: src },
        types::Ipv4Addr { addr: dst },
        payload,
    );
}

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
    try_send: tcp::async_try_send,
    register_send_waker: tcp::register_send_waker,
    clear_send_waker: tcp::clear_send_waker,
};

/// Bare-metal UDP backend vtable. No `bind` / `unbind` — routing
/// is purely `UDP_REGISTRY` lookups on the NIC RX path.
static BARE_UDP_BACKEND: uni_runtime::net::UdpBackend = uni_runtime::net::UdpBackend {
    bind: None,
    unbind: None,
    send: udp::send,
};

pub fn init_stack() {
    REGISTRY.register(protocol::Slot::Tcp, tcp_dispatch);
    REGISTRY.register(protocol::Slot::Udp, udp_dispatch);
    // Wire up the async `uni::runtime::TcpListener` reactor and
    // the per-stream recv/send reactors — all via a single backend
    // vtable. Listening requires one slot per core (each core
    // owns its own per-port accept pool); accept reads the
    // current core's pool and returns the first Established+
    // !accepted conn.
    uni_runtime::net::register_tcp_backend(&BARE_TCP_BACKEND);
    // UDP backend — lets `UdpSocket::send_to` hand off datagrams
    // without apps having to go through the legacy `uni::udp_send`
    // free function.
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

fn tcp_backend_accept(port: u16) -> uni_runtime::net::RawTcpStream {
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
static WAKEUP: [core::sync::atomic::AtomicBool; percpu::MAX_CORES] =
    [const { core::sync::atomic::AtomicBool::new(false) }; percpu::MAX_CORES];

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
static JUST_DISTRIBUTED: [core::sync::atomic::AtomicBool; percpu::MAX_CORES] =
    [const { core::sync::atomic::AtomicBool::new(false) }; percpu::MAX_CORES];


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
        && JUST_DISTRIBUTED[my_core as usize]
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
    for i in 0..num_cores as usize {
        WAKEUP[i].store(false, core::sync::atomic::Ordering::Relaxed);
    }

    let count = uni_drivers::net::poll(distribute_frame);

    // Mark ourselves as "just distributed" — our next poll attempt will
    // yield, giving other cores first shot at the lock.
    if num_cores > 1 {
        JUST_DISTRIBUTED[my_core as usize]
            .store(true, core::sync::atomic::Ordering::Relaxed);
    }

    // Release lock.
    RX_LOCK.store(0, core::sync::atomic::Ordering::Release);

    let had_frames = count > 0;
    if had_frames {
        // Wake only the specific cores that received inbox data.
        // Broadcast wake_cores() is expensive on HVF: each SGI causes
        // a WFI wake (~5µs) on every core, even if it has no work.
        for i in 1..num_cores as usize {
            if WAKEUP[i].load(core::sync::atomic::Ordering::Relaxed) {
                #[cfg(target_arch = "aarch64")]
                uni_kernel::aarch64::smp::send_sgi_to(i as u32);
                #[cfg(target_arch = "x86_64")]
                uni_kernel::send_ipi(i as u32);
            }
        }
    }

    // Flush TX (APs may have responded during distribution).
    uni_drivers::net::flush_tx_staging();

    had_frames
}

/// Classify a frame and distribute it to the appropriate core.
/// Called as the VirtIO poll callback on core 0.
fn distribute_frame(frame: &[u8]) {
    let num_cores = percpu::num_cores();

    // Parse enough of the frame to classify by protocol and flow.
    if let Some((src_mac, ethertype, payload)) = ethernet::ethernet_parse_full(frame) {
        match ethertype {
            ethernet::ETHERTYPE_ARP => {
                // ARP: always core 0 (modifies shared ARP cache).
                arp::arp_receive(payload);
            }
            ethernet::ETHERTYPE_IPV4 => {
                if let Some(pkt) = ipv4::ipv4_receive(payload) {
                    // Snoop (src_ip, src_mac) into the ARP fast cache if
                    // the peer is on our subnet.
                    if ipv4::same_subnet(pkt.src) {
                        arp::arp_learn(pkt.src, src_mac);
                    }
                    // Extract ports for flow hash (TCP and UDP both have ports at offset 0-3).
                    let (src_port, dst_port) = if pkt.payload.len() >= 4 {
                        (u16::from_be_bytes([pkt.payload[0], pkt.payload[1]]),
                         u16::from_be_bytes([pkt.payload[2], pkt.payload[3]]))
                    } else {
                        (0, 0)
                    };
                    let target = flow_hash(
                        pkt.src.addr, pkt.dst.addr, src_port, dst_port, num_cores,
                    );

                    let my_core = uni_kernel::cpu_id();
                    if target == my_core || num_cores <= 1 {
                        // Target is this core (or we're running
                        // single-core) — dispatch inline via the
                        // protocol registry. Unknown protocols fall
                        // through silently, same as the previous
                        // hardcoded match.
                        REGISTRY.dispatch(
                            pkt.protocol, pkt.src.addr, pkt.dst.addr, pkt.payload,
                        );
                    } else {
                        // Distribute to target core's RX inbox.
                        // SAFETY: percpu::init() runs before any AP starts;
                        // target is bounded by num_cores. The inbox uses
                        // SPSC discipline (single producer = the distributor
                        // here, single consumer = the target core's
                        // net_drain_cb).
                        let core = unsafe { percpu::get(target) };
                        if core.rx_inbox.push(frame) {
                            WAKEUP[target as usize].store(
                                true,
                                core::sync::atomic::Ordering::Relaxed,
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Process a single received frame through the full stack.
/// Called on core 0 for single-core mode and ARP/TCP frames,
/// and on any core for distributed frames via ap_poll.
pub fn net_receive(frame: &[u8]) {
    if let Some((src_mac, ethertype, payload)) = ethernet::ethernet_parse_full(frame) {
        match ethertype {
            ethernet::ETHERTYPE_ARP => arp::arp_receive(payload),
            ethernet::ETHERTYPE_IPV4 => {
                if let Some(pkt) = ipv4::ipv4_receive(payload) {
                    // See matching comment in distribute_frame.
                    if ipv4::same_subnet(pkt.src) {
                        arp::arp_learn(pkt.src, src_mac);
                    }
                    REGISTRY.dispatch(
                        pkt.protocol, pkt.src.addr, pkt.dst.addr, pkt.payload,
                    );
                }
            }
            _ => {}
        }
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
    let core = percpu::percore(&cc); // SAFE access via the token
    let mut did_work = false;
    let mut buf = [0u8; 1514];
    while let Some(len) = core.rx_inbox.pop_into(&mut buf) {
        net_receive(&buf[..len]);
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

