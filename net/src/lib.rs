// Network stack umbrella. See docs/networking.md for the Tier 1 vs
// Tier 2 dispatch design.
//
// The crate is split into focused modules — see each for detail:
//   * `sched`   — RX poll scheduling (Tier 1 / Tier 2 dispatch).
//   * `rx`      — the receive pipeline (Ethernet → L3 → L4).
//   * `ipv6_nd` — the IPv6 control plane (SLAAC / RA / NDP / ICMPv6).
// This file is the crate root: backend-vtable wiring, stack
// bring-up, and the re-exported public API.

#![no_std]

extern crate alloc;
extern crate nic;
extern crate uni_iobuf;
extern crate uni_kernel;
extern crate uni_runtime;

extern crate net_rx;

pub extern crate net_arp as arp;
pub extern crate net_dhcp as dhcp;
pub extern crate net_eth_tx as eth_tx;
pub extern crate net_ethernet as ethernet;
pub extern crate net_icmpv6 as icmpv6;
pub extern crate net_ipv4 as ipv4;
pub extern crate net_ipv6 as ipv6;
pub extern crate net_ipv6_send as ipv6_send;
pub extern crate net_ndp as ndp;
pub extern crate net_tcp as tcp;
pub extern crate net_types as types;
pub extern crate net_udp as udp;

use uni_kernel::percpu;

mod ipv6_nd;
mod rx;
mod sched;

// The split moved these entry points into modules; re-export them so
// the crate's public API surface is unchanged.
pub use crate::ipv6_nd::init_ipv6;
pub use crate::rx::net_receive;
pub use crate::sched::{init_eventloop, poll};

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
    do_recv_chunk: Some(tcp::do_recv_chunk),
    set_chunk_buf_slot: Some(tcp::set_chunk_buf_slot),
    clear_chunk_buf_slot: Some(tcp::clear_chunk_buf_slot),
    close: tcp::close,
    try_send: tcp::async_try_send_chain,
    register_send_waker: tcp::register_send_waker,
    clear_send_waker: tcp::clear_send_waker,
    try_send_tso: Some(tcp::try_send_tso),
    shutdown_all: Some(bare_shutdown_all),
};

/// Wrapper around `tcp::shutdown_all` that flushes the NIC TX
/// staging + queue-notify after the RST sweep so the host observes
/// the RSTs before `arch::shutdown()` returns. Bare-metal backend
/// glue — lives here, where the `TcpBackend` vtable is assembled.
fn bare_shutdown_all() {
    tcp::shutdown_all();
    nic::flush_tx_staging();
    nic::flush_tx_kick_if_dirty();
}

/// Bare-metal UDP backend vtable. No `bind` / `unbind` — routing
/// is purely `UDP_REGISTRY` lookups on the NIC RX path.
static BARE_UDP_BACKEND: uni_runtime::net::UdpBackend = uni_runtime::net::UdpBackend {
    bind: None,
    unbind: None,
    send: udp::send,
    acquire_tx_buf: Some(nic::acquire_tx_buf),
    send_via_tx_handle: Some(udp::send_via_tx_handle),
    send_with_l2_headroom: Some(udp::send_with_l2_headroom),
};

pub fn init_stack() {
    // Per-core flag tables sized to actual core count. Must run
    // before any `poll_tier2` call dereferences them.
    let n = uni_kernel::percpu::num_cores();
    sched::WAKEUP.init(n, |_| core::sync::atomic::AtomicBool::new(false));
    sched::JUST_DISTRIBUTED.init(n, |_| core::sync::atomic::AtomicBool::new(false));
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
pub fn bringup_static(ip: types::Ipv4Addr, gateway: types::Ipv4Addr, netmask: types::Ipv4Addr) {
    let ip_o = ip.octets();
    let mask_o = netmask.octets();
    let gw_o = gateway.octets();
    dhcp::set_fallback_config(
        ip_o[0], ip_o[1], ip_o[2], ip_o[3], mask_o[0], mask_o[1], mask_o[2], mask_o[3], gw_o[0],
        gw_o[1], gw_o[2], gw_o[3], 0, 0, 0, 0, // DNS — unused
    );
}
