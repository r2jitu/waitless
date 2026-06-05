// tools/hvf-runner/src/userspace_net/mod.rs
//
// Userspace TCP/IP proxy — zero-copy, no intermediate buffers.
//
// Architecture (see MEMORY.md's "HVF Runner" section for the full
// picture):
//
// - Every vCPU thread inline-polls every TCP listen fd alongside
//   its own conn fds. When a new SYN arrives, whichever vCPU's
//   `poll` returns first calls `accept()` and takes ownership of
//   the new `ProxyConn` in its own `WORKERS[id]`. macOS serializes
//   accept across threads on the same listen fd, so only one vCPU
//   wins per accept; the others see `EAGAIN`. This replaces the
//   earlier "dedicated accept thread + round-robin target picker +
//   per-target mutex handoff + wake pipe doorbell" chain, which
//   was a hard ~2500 hs/s ceiling across all vCPU counts — the
//   accept thread itself was the serialization point. First-come-
//   first-served accept across vCPUs gives natural load balancing
//   (busy vCPUs shed work to idle ones) and removes the cross-
//   thread mutex contention on `tx_replies`/`conns`.
//
// - Each vCPU thread owns its `IoState` (`VCPU_IOS[id]`) and runs
//   `vcpu_poll()` between `hv_vcpu_run` invocations. Per tick it
//   drains `tx_replies`, polls its own wake pipe + UDP relay
//   sibling + TCP listen fds + assigned TCP conn fds, accepts any
//   new connections, and injects replies straight into its
//   queue-pair's RX ring. No separate RX worker threads.
//
// - UDP uses per-vCPU SO_REUSEPORT sibling sockets; the kernel
//   distributes incoming datagrams across the group by 4-tuple hash,
//   so no software RSS is needed on the UDP path.
//
// ── SAFETY contract for the libc FFI in this module ───────────────
//
// Every `unsafe { libc::* }` call site in this file relies on the
// same small set of invariants:
//
// 1. All `sockaddr_in` pointers are stack locals we wrote ourselves
//    right before the call; the referenced memory is live for the
//    duration.
//
// 2. `recvfrom` / `sendto` / `read` / `write` / `recv` / `send`
//    buffers are either stack arrays on `IoState` or raw pointers
//    into guest RAM returned by `QueueSnapshot::gpa_to_host`. Guest
//    RAM lives for the whole VM lifetime (see `vm.rs` SAFETY
//    contract); the `IoState` buffers live as long as the enclosing
//    `Mutex<IoState>` lock, which the calling thread holds.
//
// 3. `inject_frame` / `write_tcp_frame_around_payload` cast the host
//    pointer returned by `gpa_to_host` to `*mut u8` and write up to
//    `MAX_REPLY_FRAME` / `HDR_LEN + MAX_PAYLOAD` bytes. The virtio
//    descriptor size is checked against these constants by the
//    guest driver (we trust the guest to size its own RX buffers).
//
// 4. The `dsb sy` / `dc cvau` inline asm is `options(nostack)` with
//    one register input (`addr`) and no memory effects; it can't
//    alias anything visible to Rust.
//
// Call sites that break from this pattern carry their own SAFETY
// comment inline.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::hvf;
use crate::virtio;

// ── Submodules ──────────────────────────────────────────────────
// The userspace proxy was one ~3.2k-line file; it is now split by
// role. This root keeps the engine — shared constants and state,
// socket setup, the per-vCPU poll loop, port allocation — and the
// three submodules below own the packet-flow stages.
mod frame; // pure packet construction (builders + checksums)
mod guest_tx; // guest -> host: ARP / IPv4 / IPv6 / TCP / UDP / DHCP
mod inbound; // host -> guest: listener threads, flow hash, RX inject

use frame::*;
use guest_tx::*;
use inbound::*;

const VIRTIO_NET_HDR_SIZE: usize = 12;
const GW_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const VM_IP: [u8; 4] = [10, 0, 2, 15];
const GW_IP: [u8; 4] = [10, 0, 2, 2];
const BROADCAST_IP: [u8; 4] = [255, 255, 255, 255];

/// Gateway's IPv6 link-local. Derived from `GW_MAC` via modified
/// EUI-64 (RFC 4291) so the address is deterministic and visible
/// to anyone reading the runner's NDP behaviour. The runner does
/// NOT yet bridge L4 IPv6 traffic to host sockets — this is just
/// enough plumbing to answer the VM's Neighbor Solicitations and
/// echo ICMPv6 pings, so the kernel-side IPv6 stack can be
/// exercised without a full v6 NAT bring-up.
const GW_IPV6: [u8; 16] = [
    0xfe,
    0x80,
    0,
    0,
    0,
    0,
    0,
    0,
    GW_MAC[0] ^ 0x02,
    GW_MAC[1],
    GW_MAC[2],
    0xff,
    0xfe,
    GW_MAC[3],
    GW_MAC[4],
    GW_MAC[5],
];

/// Protocol for a user-specified port forward.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// A single `host:guest` forward rule, either TCP or UDP.
///
/// The CLI parses `-p tcp:H:G` / `-p udp:H:G` into a `Vec<PortMapping>`
/// which is passed to `start()`. Multiple forwards of the same proto are
/// supported; each gets its own listen socket.
#[derive(Clone, Copy, Debug)]
pub struct PortMapping {
    pub proto: Proto,
    pub host: u16,
    pub guest: u16,
}

/// Fixed-size frame buffer — eliminates per-request heap allocation.
/// Covers all reply frame types: TCP ACK (66B), ARP (54B), DHCP (~400B).
const MAX_REPLY_FRAME: usize = 600;

#[derive(Clone, Copy)]
struct TxFrame {
    data: [u8; MAX_REPLY_FRAME],
    len: u16,
}

impl TxFrame {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ConnState {
    SynSent = 0,
    Established = 1,
    /// The proxy has sent its FIN to the guest (the host socket hit
    /// EOF) and is waiting for the guest's own FIN to finish the
    /// four-way close. Distinct from `Closed` so the conn is kept
    /// around long enough to acknowledge that FIN — without the ACK
    /// the guest strands the connection in LastAck. Ordered below
    /// `Closed` so the `state < Closed` reap guard keeps it alive.
    FinWait = 2,
    Closed = 3,
}

struct ProxyConn {
    host_fd: i32,
    src_port: u16,
    /// Guest-side listening port that this connection targets — used as
    /// the `dst_port` in every TCP frame we synthesize for the guest.
    /// Populated from the `PortMapping` the listen socket was created for.
    guest_port: u16,
    my_seq: u32,
    peer_ack: u32,
    state: ConnState,
    pending: Vec<u8>,
    /// IP family of this connection — determines whether reply frames
    /// are built via the v4 (`GW_IP`/`VM_IP`) or v6 (`GW_IPV6`/`VM_IPV6`)
    /// frame builders. Inherited from the `TcpListen` whose `accept(2)`
    /// produced this conn.
    family: IpFamily,
}

// Per-worker shared state. In the N-worker design, each queue pair has
// one dedicated RX worker thread paired with one vCPU thread. All the
// shared state that was previously global (CONNS, TX_REPLIES,
// UDP_CLIENTS) is now per-worker: producer and consumer are both
// scoped to a single (worker, vCPU) pair, so mutexes are contended by
// at most 2 threads instead of N+N.
struct WorkerShared {
    /// TCP connections accepted by this worker's listen fds. Keyed by
    /// the guest-visible pseudo-ephemeral `src_port` we assigned when
    /// synthesising the SYN. Lookups in `handle_tcp` (vCPU side) and
    /// accept/read paths (worker side) both hit this map.
    conns: Mutex<HashMap<u16, ProxyConn>>,
    /// Reply frames produced by the vCPU thread (ARP responses, TCP
    /// SYN-ACK/ACK/FIN control frames, DHCP replies). The worker
    /// drains this at the top of its poll loop and injects them into
    /// its own RX queue. Single producer (one vCPU) + single consumer
    /// (one worker) = low contention.
    tx_replies: Mutex<VecDeque<TxFrame>>,
    /// UDP return-path lookup: `(guest_port, client_ephemeral_port)` →
    /// external sockaddr. Populated by the worker on incoming UDP, read
    /// by the vCPU in `handle_udp_v4` when the guest sends a reply.
    udp_clients: Mutex<HashMap<(u16, u16), libc::sockaddr_in>>,
    /// IPv6 counterpart to `udp_clients`. Same `(guest_port,
    /// client_ephemeral_port)` key, value is `sockaddr_in6` so the
    /// TX-side reply in `handle_udp_v6` can `sendto` the original
    /// peer over IPv6.
    udp_clients_v6: Mutex<HashMap<(u16, u16), libc::sockaddr_in6>>,
    /// MTU-sized inbound frames staged by another vCPU's
    /// `handle_udp_rx` for THIS vCPU's RX queue. Cross-vCPU
    /// 4-tuple-hash UDP routing — necessary because macOS's
    /// shared-fd UDP recv distributes by recvfrom race instead of
    /// 4-tuple, so a stateful protocol like QUIC sees its own
    /// connection's packets scatter across vCPUs randomly. The
    /// receiving vCPU computes a hash on the 4-tuple, and if the
    /// target isn't itself, it pushes the built Ethernet frame
    /// here for the owning vCPU to inject on its next poll.
    /// Vec<u8> rather than `TxFrame` (which is 600-byte fixed) so
    /// MTU-1500 datagrams + 42-byte L2/L3/L4 headers fit.
    /// Multi-producer (any vCPU) + single-consumer (this vCPU's
    /// poll loop), so the Mutex is contended at most by
    /// `cpu_count` threads.
    forwarded_rx: Mutex<VecDeque<Vec<u8>>>,
}

impl WorkerShared {
    fn new() -> Self {
        Self {
            conns: Mutex::new(HashMap::new()),
            tx_replies: Mutex::new(VecDeque::new()),
            udp_clients_v6: Mutex::new(HashMap::new()),
            udp_clients: Mutex::new(HashMap::new()),
            forwarded_rx: Mutex::new(VecDeque::new()),
        }
    }
}

/// Array of per-worker shared state. Populated once by `start()` with
/// exactly `cpu_count` entries; readers index by their worker id (for
/// worker threads) or `CURRENT_VCPU.get()` (for vCPU threads).
static WORKERS: OnceLock<Vec<WorkerShared>> = OnceLock::new();

/// Per-vCPU IoState: the host-fd-side state that used to live on the
/// stack of a dedicated worker thread. With the inline-poll design,
/// the vCPU thread itself reaches in and runs one polling iteration
/// before re-entering `hv_vcpu_run`. There is no contention on the
/// outer `Mutex` — only the matching vCPU thread ever takes it — but
/// `Mutex` is convenient for `Send + Sync`.
static VCPU_IOS: OnceLock<Vec<Mutex<IoState>>> = OnceLock::new();

/// Total vCPU count (==# of workers/queue pairs). Stored once by
/// `start()` so `vcpu_poll()` can pick the right `single_queue` mode
/// without threading the count through every call.
static CPU_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Global atomic source-port allocator for incoming TCP connections.
/// Each accept across *any* vCPU grabs the next value via fetch_add,
/// wrapping in [40000, 60000). Keeps the guest-visible 5-tuples unique
/// across vCPUs without partitioning the port space.
static NEXT_PROXY_SRC_PORT: AtomicU16 = AtomicU16::new(40000);

/// TCP listen fds published once by `start()`. Every vCPU's
/// `vcpu_poll` reads this slice and adds the fds to its own
/// `pollfds` array, so any vCPU whose poll wakes first can accept
/// the new connection. macOS serializes `accept(2)` internally
/// across threads on the same fd, so concurrent vCPUs racing on
/// accept is safe — exactly one wins, the rest see `EAGAIN`.
static LISTENS: OnceLock<Vec<TcpListen>> = OnceLock::new();

/// Per-vCPU wake pipe. Used by `wake_all_vcpus()` (e.g. from the
/// stdin reader thread so any parked `vcpu_poll` returns promptly)
/// and by any other code that needs to kick a specific vCPU out of
/// its cooperative-yield poll. TCP accepts used to go through
/// these too, but the inline-accept design doesn't need them —
/// vCPUs see the new SYN via their own listen-fd poll.
struct WakePipe {
    read_fd: i32,
    write_fd: i32,
}

static VCPU_WAKE_PIPES: OnceLock<Vec<WakePipe>> = OnceLock::new();

fn make_wake_pipe() -> Result<WakePipe, String> {
    let mut fds = [0i32; 2];
    let r = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if r != 0 {
        return Err(format!("pipe: {}", std::io::Error::last_os_error()));
    }
    unsafe {
        libc::fcntl(fds[0], libc::F_SETFL, libc::O_NONBLOCK);
        libc::fcntl(fds[1], libc::F_SETFL, libc::O_NONBLOCK);
    }
    Ok(WakePipe {
        read_fd: fds[0],
        write_fd: fds[1],
    })
}

/// Doorbell every registered vCPU. Used by the stdin reader thread
/// after pushing a byte into `pl011::RX_BUF` so any parked vCPU wakes
/// from its cooperative yield loop promptly instead of waiting up to
/// the next 10 ms `vcpu_poll` timeout. No-op if `start()` hasn't run
/// (which can happen if userspace_net init failed before vCPUs exist).
pub fn wake_all_vcpus() {
    if let Some(pipes) = VCPU_WAKE_PIPES.get() {
        let buf = [0u8; 1];
        for p in pipes {
            unsafe {
                libc::write(p.write_fd, buf.as_ptr() as *const _, 1);
            }
        }
        for i in 0..pipes.len() {
            crate::vm::wake_vcpu(i);
        }
    }
}

/// Look up shared state for a worker/vCPU. Panics only if `start()`
/// hasn't run, which shouldn't happen since both worker and vCPU
/// threads are spawned after `start()` populates `WORKERS`.
fn worker_shared(id: usize) -> &'static WorkerShared {
    let workers = WORKERS.get().expect("WORKERS not initialised");
    &workers[id.min(workers.len() - 1)]
}

/// Look up the current vCPU's worker-shared state. Called from vCPU
/// threads (handle_tcp/handle_udp_v4/handle_guest_tx) where the current
/// vCPU id is published by `process_tx_queue` into `CURRENT_VCPU`.
fn my_worker_shared() -> &'static WorkerShared {
    let id = CURRENT_VCPU.with(|c| c.get());
    worker_shared(id)
}

/// UDP relay table: one entry per `-p udp:H:G` forward. Each entry
/// stores `cpu_count` sibling sockets all bound to the same host port
/// via `SO_REUSEPORT`, plus the guest port. Incoming datagrams are
/// distributed across the siblings by the kernel (io_thread polls all
/// of them), and reply sends pick `fds[current_vcpu]` so multi-core
/// TX doesn't serialise on one kernel socket. All siblings share the
/// same source port, so replies carry the original relay port as their
/// source — NAT-correct.
///
/// Published once by `start()` before the io_thread or any vCPU runs,
/// so readers can rely on observing the fully-initialised table.
struct UdpRelayFds {
    guest_port: u16,
    fds: Vec<i32>,
}
static UDP_RELAYS: OnceLock<Vec<UdpRelayFds>> = OnceLock::new();

/// IPv6 counterpart to `UDP_RELAYS`. Same shape — keyed by
/// `guest_port`, holds `cpu_count` v6 sibling fds (one per vCPU
/// for the TX-side lookup). Set at `start()` time alongside the
/// v4 table.
static UDP_RELAYS_V6: OnceLock<Vec<UdpRelayFds>> = OnceLock::new();

const GUEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

/// Per-listen-socket state.
///
/// One `TcpListen` per `(host_port, family)` pair: `start()` calls
/// `bind_listen_v4` for AF_INET and (best-effort) `bind_listen_v6` for
/// AF_INET6, so a single `-p tcp:H:G` mapping yields up to two
/// entries here. Inline-accept polls every entry; the family tag
/// propagates into the `ProxyConn` we synthesise so downstream
/// reply frames pick the right builder.
#[derive(Clone, Copy)]
struct TcpListen {
    fd: i32,
    guest_port: u16,
    family: IpFamily,
}

// One UDP-relay sibling, scoped to a single vCPU's IoState. The
// enclosing relay opens `cpu_count` SO_REUSEPORT-bound siblings at
// `start()` time; vCPU `N` owns sibling `N`, and `UDP_RELAYS` below
// keeps a flat `Vec<i32>` so the TX-side `handle_udp_v4` can still look
// up "this vCPU's sibling" when the guest sends a reply.

/// IP family tag shared by `TcpListen`, `ProxyConn`, and the UDP
/// listener thread's per-fd table.
/// Used by the per-vCPU poll loop to dispatch the right frame
/// builder when injecting RX frames back into the guest.
#[derive(Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
}

/// Source/destination IP-address pair, family-tagged. Pairs the
/// addresses with their family so `write_tcp_frame*` can branch
/// internally on a single argument instead of every call site
/// having a `match family { V4 => ..., V6 => ... }` block.
#[derive(Clone, Copy)]
enum IpAddrPair {
    V4 { src: [u8; 4], dst: [u8; 4] },
    V6 { src: [u8; 16], dst: [u8; 16] },
}

impl IpAddrPair {
    /// Length of the IP header on the wire — 20 (v4) or 40 (v6).
    #[inline]
    fn ip_hdr_len(&self) -> usize {
        match self {
            IpAddrPair::V4 { .. } => 20,
            IpAddrPair::V6 { .. } => 40,
        }
    }

    /// Ethertype field (host order) for the L2 header.
    #[inline]
    fn ethertype(&self) -> u16 {
        match self {
            IpAddrPair::V4 { .. } => 0x0800,
            IpAddrPair::V6 { .. } => 0x86dd,
        }
    }

    /// Write the IP header into `buf[..ip_hdr_len()]`. `tcp_len` is
    /// `TCP header + payload` bytes — the v4 header's `total_length`
    /// includes itself + tcp_len, while v6's `payload_length` is
    /// just tcp_len. Caller must zero/initialise the rest of `buf`
    /// (TCP header, payload) separately.
    fn write_ip_header(&self, buf: &mut [u8], tcp_len: usize) {
        match *self {
            IpAddrPair::V4 { src, dst } => {
                buf[0] = 0x45;
                buf[1] = 0;
                let ip_total = (20 + tcp_len) as u16;
                buf[2..4].copy_from_slice(&ip_total.to_be_bytes());
                buf[4..8].copy_from_slice(&[0, 0, 0x40, 0]);
                buf[8] = 64; // TTL
                buf[9] = 6; // protocol = TCP
                buf[10..12].fill(0); // checksum placeholder
                buf[12..16].copy_from_slice(&src);
                buf[16..20].copy_from_slice(&dst);
                let cs = ipv4_checksum(&buf[..20]);
                buf[10] = (cs >> 8) as u8;
                buf[11] = (cs & 0xff) as u8;
            }
            IpAddrPair::V6 { src, dst } => {
                buf[..4].copy_from_slice(&0x6000_0000u32.to_be_bytes());
                buf[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
                buf[6] = 6; // next_header = TCP
                buf[7] = 64; // hop limit
                buf[8..24].copy_from_slice(&src);
                buf[24..40].copy_from_slice(&dst);
            }
        }
    }

    /// Compute the TCP checksum over `tcp_seg` (TCP header + payload)
    /// using the family-correct pseudo-header form. v4 uses
    /// `tcp_checksum`'s pseudo-header; v6 uses the
    /// `next_header = TCP` form.
    fn tcp_checksum(&self, tcp_seg: &[u8]) -> u16 {
        match self {
            IpAddrPair::V4 { src, dst } => tcp_checksum(src, dst, tcp_seg),
            IpAddrPair::V6 { src, dst } => ipv6_pseudo_checksum(src, dst, 6, tcp_seg),
        }
    }
}

/// Per-vCPU IoState. One per vCPU; lives in `VCPU_IOS` and is locked
/// only by the vCPU thread that owns it. TCP listen fds live in the
/// shared `LISTENS` slice and every vCPU adds them to its own
/// `pollfds`; whichever vCPU's `poll` wakes on a listen fd first
/// calls `accept()` and inserts the new `ProxyConn` into its own
/// `WORKERS[id]`. The per-iteration poll set is: wake pipe, UDP
/// siblings, TCP listen fds, and assigned TCP conn fds.
struct IoState {
    /// The vCPU's id (== its queue pair).
    id: usize,
    /// Outbound UDP NAT — guest_src_port → host-side fd we
    /// allocated to forward this flow. Populated lazily on first
    /// `handle_udp_outbound`; the fd lives until vCPU teardown.
    /// Each fd is registered in `pollfds` so reply datagrams wake
    /// this vCPU and we synthesise a UDP frame back into the
    /// guest's RX queue. Single-owner per vCPU — no cross-thread
    /// mutation, no SO_REUSEPORT.
    outbound_udp: HashMap<u16, OutboundUdp>,
    /// Read end of the per-vCPU wake pipe. Polled in `pollfds` so a
    /// write from the accept thread breaks the blocking poll. The
    /// payload is a doorbell — drained and discarded.
    wake_pipe_read: i32,
    guest_mac: [u8; 6],
    read_buf: [u8; 2048],
    rx_last: u16,
    pollfds: Vec<libc::pollfd>,
    /// Guest-visible ephemeral src_port for each `Conn`-slot pollfd.
    /// Indices `[0, fixed_slots)` map to wake pipe / udps and are
    /// filled with 0 placeholders; only `[fixed_slots..]` entries
    /// are valid.
    conn_ports: Vec<u16>,
    frame_buf: [u8; 2048],
    /// vCPU 0 broadcasts a gratuitous ARP on its first iteration so
    /// the host learns our MAC. Bookkeeping kept here so it survives
    /// across `vcpu_poll` calls.
    primed: bool,
    /// Drives the periodic closed-conn cleanup pass.
    cleanup_ctr: u32,
}

/// One outbound UDP flow allocated by `handle_udp_outbound`. The
/// guest sends from `guest_src_port` to some external host:port;
/// we forward via `fd` (an unbound non-blocking socket) and remember
/// the original destination so reply frames can carry the right
/// `(src_ip, src_port)` back to the guest.
#[derive(Clone, Copy)]
struct OutboundUdp {
    fd: i32,
    last_dst_ip: [u8; 4],
    last_dst_port: u16,
}

/// Open a non-blocking TCP listen socket bound to
/// `(127.0.0.1, host_port)`. Only one fd per `-p tcp:` mapping —
/// published in `LISTENS` and polled inline by every vCPU thread.
/// macOS doesn't distribute TCP across `SO_REUSEPORT` listener
/// siblings, so we rely on `accept(2)` itself being safe across
/// concurrent callers on the same fd: whichever vCPU's `poll`
/// wakes first grabs the connection, the rest see `EAGAIN`.
fn bind_listen_v4(host_port: u16) -> Result<i32, String> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(format!("tcp socket(): {}", std::io::Error::last_os_error()));
        }
        let one: i32 = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const _,
            4,
        );
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as u8;
        addr.sin_port = host_port.to_be();
        addr.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();
        if libc::bind(
            fd,
            &addr as *const _ as *const _,
            std::mem::size_of_val(&addr) as u32,
        ) < 0
        {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(format!("tcp bind({host_port}): {e}"));
        }
        // 4096-deep accept queue. macOS silently caps to
        // `kern.ipc.somaxconn` (default 128), so the OS effective
        // value is whatever sysctl reports — but raising it past
        // any plausible cap is harmless and lets benchmarks at
        // thousand-conn scale work on hosts where the operator has
        // bumped somaxconn (`sudo sysctl -w kern.ipc.somaxconn=4096`).
        libc::listen(fd, 4096);
        libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
        Ok(fd)
    }
}

/// IPv6 sibling of `bind_listen_v4`. Same shape but AF_INET6 +
/// `IPV6_V6ONLY=1` bound to `[::1]:host_port`, so v4 and v6
/// listeners on the same host port stay disjoint (no
/// `::ffff:1.2.3.4` mapped weirdness on accept). Best-effort: a
/// failure here just means v6 traffic doesn't reach the guest
/// over this mapping; the v4 listener stays up.
fn bind_listen_v6(host_port: u16) -> Result<i32, String> {
    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(format!(
                "tcp v6 socket(): {}",
                std::io::Error::last_os_error()
            ));
        }
        let one: i32 = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const _,
            4,
        );
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &one as *const _ as *const _,
            4,
        );
        let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
        addr.sin6_family = libc::AF_INET6 as u8;
        addr.sin6_port = host_port.to_be();
        // `s6_addr[15] = 1` is `::1`, mirroring the v4 `127.0.0.1`
        // bind so non-loopback v6 traffic doesn't accidentally hit
        // the relay.
        addr.sin6_addr.s6_addr[15] = 1;
        if libc::bind(
            fd,
            &addr as *const _ as *const _,
            std::mem::size_of_val(&addr) as u32,
        ) < 0
        {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(format!("tcp v6 bind([::1]:{host_port}): {e}"));
        }
        libc::listen(fd, 4096);
        libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
        Ok(fd)
    }
}

/// Open a UDP sibling socket: `SO_REUSEPORT`-bound to
/// `(127.0.0.1, host_port)`, `O_NONBLOCK`, with 16 MiB send and
/// receive buffers. All siblings of a relay share one port; the
/// kernel distributes incoming packets across them and reply sends
/// go out whichever one the current vCPU picks.
fn open_udp_sibling_v4(host_port: u16) -> Result<i32, String> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(format!("udp socket(): {}", std::io::Error::last_os_error()));
        }
        let one: i32 = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const _,
            4,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &one as *const _ as *const _,
            4,
        );
        // Big buffers so bursty UDP doesn't drop at the host kernel.
        let bufsz: i32 = 16 * 1024 * 1024;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &bufsz as *const _ as *const _,
            4,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &bufsz as *const _ as *const _,
            4,
        );
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as u8;
        addr.sin_port = host_port.to_be();
        addr.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();
        if libc::bind(
            fd,
            &addr as *const _ as *const _,
            std::mem::size_of_val(&addr) as u32,
        ) < 0
        {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(format!("udp bind({host_port}): {e}"));
        }
        libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
        Ok(fd)
    }
}

/// IPv6 sibling of `open_udp_sibling_v4`. Binds to `[::1]:host_port`
/// with `IPV6_V6ONLY=1` so v4 traffic still goes to the AF_INET
/// sibling — keeps the receive-path code paths cleanly separated
/// (v4 sees `sockaddr_in`, v6 sees `sockaddr_in6`, no
/// `::ffff:1.2.3.4` mapped weirdness).
fn open_udp_sibling_v6(host_port: u16) -> Result<i32, String> {
    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(format!(
                "udp v6 socket(): {}",
                std::io::Error::last_os_error()
            ));
        }
        let one: i32 = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const _,
            4,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &one as *const _ as *const _,
            4,
        );
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &one as *const _ as *const _,
            4,
        );
        let bufsz: i32 = 16 * 1024 * 1024;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &bufsz as *const _ as *const _,
            4,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &bufsz as *const _ as *const _,
            4,
        );
        let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
        addr.sin6_family = libc::AF_INET6 as u8;
        addr.sin6_port = host_port.to_be();
        // Bind to ::1 (loopback) so non-loopback traffic doesn't
        // accidentally hit the relay; mirrors the v4 `127.0.0.1`
        // bind. `s6_addr[15] = 1` is `::1`.
        addr.sin6_addr.s6_addr[15] = 1;
        if libc::bind(
            fd,
            &addr as *const _ as *const _,
            std::mem::size_of_val(&addr) as u32,
        ) < 0
        {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(format!("udp v6 bind([::1]:{host_port}): {e}"));
        }
        libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
        Ok(fd)
    }
}

pub fn start(mappings: &[PortMapping], cpu_count: usize) -> Result<[u8; 6], String> {
    let mac: [u8; 6] = GUEST_MAC;
    let cpu_count = cpu_count.max(1);

    // One TCP listen fd per mapping, shared across all vCPUs. Each
    // vCPU includes every listen fd in its `vcpu_poll` pollfds;
    // whichever vCPU wakes first on a given POLLIN calls `accept()`
    // and takes ownership of the new conn locally. macOS's `accept`
    // is thread-safe on a single fd (kernel serializes), so this
    // first-come-first-served pattern needs no extra locking.
    let mut listens: Vec<TcpListen> = Vec::new();
    // UDP uses the SAME shared-fd pattern now. We previously opened
    // one SO_REUSEPORT sibling per vCPU on the theory that macOS
    // distributes UDP across siblings (it's documented to), but
    // empirically on darwin 24/M2 all packets hash to a single
    // sibling — instrumentation under `udp_peak` 2 c showed
    // vcpu0=0, vcpu1=150 000 after 6 s of load, leaving one vCPU
    // 100 % idle and the other saturated at ~25 k pkt/s.
    // A single shared fd polled by every vCPU, with `recvfrom`
    // racing at the kernel (the socket receive lock serialises),
    // gives us real load distribution on macOS. Linux still gets
    // SO_REUSEPORT-style 4-tuple hashing from its own kernel if
    // siblings ever become worth re-adding for that host.
    let mut relay_table: Vec<UdpRelayFds> = Vec::new();
    let mut relay_table_v6: Vec<UdpRelayFds> = Vec::new();

    for m in mappings {
        match m.proto {
            Proto::Tcp => {
                let fd = bind_listen_v4(m.host)?;
                listens.push(TcpListen {
                    fd,
                    guest_port: m.guest,
                    family: IpFamily::V4,
                });
                // IPv6 sibling on the same host port — failure is
                // non-fatal (e.g. ::1 not configured): we keep the
                // v4 listener and the mapping just doesn't carry
                // v6 traffic into the guest.
                match bind_listen_v6(m.host) {
                    Ok(fd6) => listens.push(TcpListen {
                        fd: fd6,
                        guest_port: m.guest,
                        family: IpFamily::V6,
                    }),
                    Err(e) => eprintln!("  warning: {e}"),
                }
            }
            Proto::Udp => {
                // Open one UDP fd per `udp:H:G` mapping. The dedicated
                // listener thread (`udp_listener_loop`) owns recvfrom
                // on every entry in `relay_table` / `relay_table_v6`
                // and 4-tuple-hashes inbound flows to vCPUs.
                //
                // The `UdpRelayFds.fds` Vec still carries `cpu_count`
                // copies of the same fd — that's a legacy shape the
                // TX-side `handle_udp_v4` reply path indexes by vCPU id
                // to pick a sibling, which used to matter under
                // SO_REUSEPORT. With one fd per relay it's the same
                // value `cpu_count` times, but kept for API symmetry.
                match open_udp_sibling_v4(m.host) {
                    Ok(fd) => {
                        let fds = vec![fd; cpu_count.max(1)];
                        relay_table.push(UdpRelayFds {
                            guest_port: m.guest,
                            fds,
                        });
                    }
                    Err(e) => eprintln!("  warning: {e}"),
                }
                // IPv6 sibling on the same host port — bind failure
                // here is also non-fatal (e.g. ::1 not configured),
                // we just log and continue with v4-only relay.
                match open_udp_sibling_v6(m.host) {
                    Ok(fd) => {
                        let fds = vec![fd; cpu_count.max(1)];
                        relay_table_v6.push(UdpRelayFds {
                            guest_port: m.guest,
                            fds,
                        });
                    }
                    Err(e) => eprintln!("  warning: {e}"),
                }
            }
        }
    }

    if !relay_table.is_empty() {
        UDP_RELAYS.set(relay_table).ok();
    }
    if !relay_table_v6.is_empty() {
        UDP_RELAYS_V6.set(relay_table_v6).ok();
    }

    // One WorkerShared entry per vCPU, populated before any vCPU runs.
    let mut workers: Vec<WorkerShared> = Vec::with_capacity(cpu_count);
    for _ in 0..cpu_count {
        workers.push(WorkerShared::new());
    }
    WORKERS.set(workers).ok();
    CPU_COUNT.store(cpu_count, Ordering::Release);

    // Per-vCPU wake pipes. No longer doorbelled by a TCP accept
    // thread (inline-accept design removed that), but still used by
    // `wake_all_vcpus()` so non-network events (stdin bytes, future
    // aux sources) can kick a parked `vcpu_poll(10ms)` out
    // immediately instead of waiting the full timeout.
    let mut wake_pipes: Vec<WakePipe> = Vec::with_capacity(cpu_count);
    for _ in 0..cpu_count {
        wake_pipes.push(make_wake_pipe()?);
    }
    let wake_reads: Vec<i32> = wake_pipes.iter().map(|p| p.read_fd).collect();
    VCPU_WAKE_PIPES.set(wake_pipes).ok();

    // Build per-vCPU IoState. TCP listen fds are shared via the
    // `LISTENS` global below, not stored per-IoState. Each IoState
    // gets the read end of its wake pipe.
    let mut vcpu_ios: Vec<Mutex<IoState>> = Vec::with_capacity(cpu_count);
    for (id, &wake_read) in wake_reads.iter().enumerate().take(cpu_count) {
        vcpu_ios.push(Mutex::new(IoState {
            id,
            outbound_udp: HashMap::new(),
            wake_pipe_read: wake_read,
            guest_mac: mac,
            read_buf: [0u8; 2048],
            rx_last: 0,
            pollfds: Vec::with_capacity(64),
            conn_ports: Vec::with_capacity(64),
            frame_buf: [0u8; 2048],
            primed: false,
            cleanup_ctr: 0,
        }));
    }
    VCPU_IOS.set(vcpu_ios).ok();

    // Publish TCP listen fds for every vCPU's inline-accept poll.
    // `LISTENS` is read-only after this point; vCPUs read it each
    // iteration to repopulate their pollfds. If there are no TCP
    // mappings the slice is empty and the listen-fd portion of the
    // poll loop is a no-op.
    LISTENS.set(listens.clone()).ok();

    eprintln!();
    eprintln!("  VM network: 10.0.2.15 (userspace, zero-copy)");
    for m in mappings.iter().filter(|m| m.proto == Proto::Tcp) {
        eprintln!("  TCP relay:  localhost:{} -> guest:{}", m.host, m.guest);
    }
    for m in mappings.iter().filter(|m| m.proto == Proto::Udp) {
        eprintln!("  UDP relay:  localhost:{} -> guest:{}", m.host, m.guest);
    }
    if let Some(first_tcp) = mappings.iter().find(|m| m.proto == Proto::Tcp) {
        eprintln!(
            "  Benchmark:  wrk -t1 -c1 -d10s http://localhost:{}/health",
            first_tcp.host
        );
    }
    eprintln!();

    // Spawn the dedicated UDP listener thread. It owns recvfrom on
    // every host UDP fd and 4-tuple-hashes inbound flows to vCPUs.
    // Spawned LAST so every static it reads — UDP_RELAYS{,_V6},
    // WORKERS, VCPU_WAKE_PIPES, CPU_COUNT — is fully published.
    spawn_udp_listener();

    Ok(mac)
}

// Per-vCPU thread-local: the id of the vCPU whose TX queue notify
// we are currently handling. Read by `handle_udp_v4` to pick the right
// per-vCPU TX fd from `UDP_RELAYS`. Set at the top of `process_tx_queue`
// from `queue_idx / 2` — in Tier 1 multi-queue, vCPU N owns TX queue
// index 2N+1, so `queue_idx / 2` is the vCPU id.
thread_local! {
    static CURRENT_VCPU: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// TX QUEUE_NOTIFY handler. Uses TX QueueSnapshot for lock-free guest
/// RAM access. Only takes DEVICE lock briefly for interrupt_status.
/// Accepts the queue index (odd = TX queue) to support multi-queue.
pub fn process_tx_queue(queue_idx: u32) {
    use std::cell::Cell;
    thread_local! {
        static TX_LAST_MAP: Cell<[u16; 9]> = const { Cell::new([0u16; 9]) };
    }
    let tx = virtio::queue_snapshot(queue_idx as usize);
    if !tx.ready {
        return;
    }

    // Map queue_idx to a slot in the per-thread last array (TX queues: 1,3,5,7,... → slots 0..8)
    let slot = (queue_idx / 2) as usize;
    if slot >= 9 {
        return;
    }

    // Remember which vCPU we're processing for — `handle_udp_v4` uses it
    // to pick its per-vCPU TX socket.
    CURRENT_VCPU.with(|c| c.set(slot));

    let avail_idx =
        unsafe { core::ptr::read_volatile(tx.gpa_to_host(tx.avail_addr + 2) as *const u16) };
    let mut lasts = TX_LAST_MAP.with(|c| c.get());
    let mut last = lasts[slot];
    if last == avail_idx {
        return;
    }

    while last != avail_idx {
        let ring_idx = last & (tx.qsize - 1);
        let desc_idx = unsafe {
            core::ptr::read_volatile(
                tx.gpa_to_host(tx.avail_addr + 4 + ring_idx as u64 * 2) as *const u16
            )
        };
        let (addr, len) = unsafe {
            let dp = tx.gpa_to_host(tx.desc_addr + desc_idx as u64 * 16);
            (
                core::ptr::read_unaligned(dp as *const u64),
                core::ptr::read_unaligned(dp.add(8) as *const u32) as usize,
            )
        };
        if len > VIRTIO_NET_HDR_SIZE {
            let frame = unsafe {
                std::slice::from_raw_parts(
                    tx.gpa_to_host(addr).add(VIRTIO_NET_HDR_SIZE),
                    len - VIRTIO_NET_HDR_SIZE,
                )
            };
            handle_guest_tx(frame);
        }
        // Update TX used ring (host-side tracking via TX_LAST).
        let used_idx = last; // host tracks its own used_idx, not guest RAM
        unsafe {
            let entry = tx.gpa_to_host(tx.used_addr + 4 + (used_idx & (tx.qsize - 1)) as u64 * 8);
            core::ptr::write_unaligned(entry as *mut u32, desc_idx as u32);
            core::ptr::write_unaligned(entry.add(4) as *mut u32, len as u32);
            core::ptr::write_volatile(
                tx.gpa_to_host(tx.used_addr + 2) as *mut u16,
                used_idx.wrapping_add(1),
            );
        }
        last = last.wrapping_add(1);
    }
    lasts[slot] = last;
    TX_LAST_MAP.with(|c| c.set(lasts));
    unsafe {
        core::arch::asm!("dsb sy", options(nostack));
    }
    // No SPI assert here — ACK frames queued in TX_REPLIES will be
    // injected by the IO thread, which asserts SPI after injection.
    // Asserting here caused a spurious interrupt (guest polls, finds
    // no new RX, wastes an MMIO exit).
}

// ── Inline polling: vCPU thread runs the worker iteration ──────────────────
//
// The vCPU thread itself owns its `IoState` (looked up in `VCPU_IOS`)
// and runs one polling iteration via `vcpu_poll()` between
// `hv_vcpu_run` invocations. Replaces the old N spawned worker threads.
//
// Each vCPU/queue-pair is the only writer to its own RX ring, so
// there's no lock on the ring itself. Shared state with the rest of
// the runner (tx_replies queue, conns map, udp_clients map) lives in
// `WORKERS[id]` and is touched only by this same vCPU thread, so the
// inner mutexes are uncontended.

/// Run one polling iteration for `vcpu_id`: drain reply frames, flush
/// pending TCP data, poll host fds with `timeout_ms`, accept incoming
/// TCP, drain UDP siblings, and stream zero-copy TCP RX into the guest
/// ring. Returns `true` if anything was injected (so an idle-loop
/// caller knows to break out and re-enter the guest).
///
/// `timeout_ms` is forwarded directly to `poll(2)`. Pass `0` for the
/// non-blocking tick before each `hv_vcpu_run`, or a small positive
/// value (e.g. 10) from the cooperative-yield idle path so the vCPU
/// blocks in `poll` instead of burning the host CPU.
pub fn vcpu_poll(vcpu_id: usize, timeout_ms: i32) -> bool {
    let ios = match VCPU_IOS.get() {
        Some(v) => v,
        None => return false,
    };
    if vcpu_id >= ios.len() {
        return false;
    }
    let cpu_count = CPU_COUNT.load(Ordering::Acquire);
    let mut io = ios[vcpu_id].lock().unwrap();
    poll_worker_iteration(&mut io, cpu_count, timeout_ms)
}

/// `dsb sy` + — in single-queue mode — the level-triggered GIC SPI
/// doorbell that tells the guest its RX ring advanced. Called after
/// every batch of injected frames. Idempotent: an extra call after a
/// no-op inject is harmless (the barrier is free, the SPI is
/// edge-cycled true→false).
fn signal_rx_doorbell(single_queue: bool) {
    // SAFETY: `dsb sy` is a bare barrier with no operands; the GIC
    // SPI calls are the documented HVF doorbell API.
    unsafe {
        core::arch::asm!("dsb sy", options(nostack));
    }
    if single_queue {
        unsafe {
            hvf::hv_gic_set_spi(35, true);
            hvf::hv_gic_set_spi(35, false);
        }
    }
}

/// Drain reply frames staged by the `guest_tx` handlers (`handle_tcp`
/// / `handle_udp_v4` / `handle_arp`) into this vCPU's RX ring.
/// Returns whether any frame was injected.
fn drain_tx_replies(
    io: &mut IoState,
    shared: &WorkerShared,
    qsnap: &virtio::QueueSnapshot,
    single_queue: bool,
) -> bool {
    let mut replies = shared.tx_replies.lock().unwrap();
    let mut any = false;
    while let Some(f) = replies.pop_front() {
        if !qsnap.ready || !inject_frame(f.as_slice(), qsnap, &mut io.rx_last) {
            replies.push_front(f);
            break;
        }
        any = true;
    }
    drop(replies);
    if any {
        signal_rx_doorbell(single_queue);
    }
    any
}

/// Drain UDP frames forwarded to this vCPU by another vCPU's
/// `handle_udp_rx` (4-tuple hash routing). Same inject pattern as
/// `drain_tx_replies`; separate because forwarded frames are
/// MTU-sized `Vec<u8>`s rather than the 600-byte fixed `TxFrame`
/// reply records.
fn drain_forwarded_rx(
    io: &mut IoState,
    shared: &WorkerShared,
    qsnap: &virtio::QueueSnapshot,
    single_queue: bool,
) -> bool {
    let mut fwd = shared.forwarded_rx.lock().unwrap();
    let mut any = false;
    while let Some(f) = fwd.pop_front() {
        if !qsnap.ready || !inject_frame(&f, qsnap, &mut io.rx_last) {
            fwd.push_front(f);
            break;
        }
        any = true;
    }
    drop(fwd);
    if any {
        signal_rx_doorbell(single_queue);
    }
    any
}

/// Flush buffered data for conns that reached `Established` while the
/// RX queue was not yet ready. Returns whether any frame was injected.
fn flush_established_pending(
    io: &mut IoState,
    shared: &WorkerShared,
    qsnap: &virtio::QueueSnapshot,
    single_queue: bool,
) -> bool {
    let mut conns = shared.conns.lock().unwrap();
    let mut flushed = false;
    for c in conns.values_mut() {
        if c.state == ConnState::Established && !c.pending.is_empty() && qsnap.ready {
            let p = std::mem::take(&mut c.pending);
            inject_data_frames(c, &p, &GUEST_MAC, qsnap, &mut io.rx_last, &mut io.frame_buf);
            flushed = true;
        }
    }
    drop(conns);
    if flushed {
        signal_rx_doorbell(single_queue);
    }
    flushed
}

/// Slot offsets into `io.pollfds` produced by `build_pollfds`.
/// `pollfds[0]` is the wake pipe; `[listen_slot_start..]` the shared
/// TCP listen fds; `[outbound_slot_start..]` the outbound-UDP NAT
/// fds; `[fixed_slots..]` this vCPU's assigned TCP conn fds.
struct PollLayout {
    listen_slot_start: usize,
    outbound_slot_start: usize,
    fixed_slots: usize,
    /// `(guest_src_port, flow)` snapshot of this vCPU's outbound-UDP
    /// table, parallel to the `outbound_slot_start` pollfd range.
    outbound_drain: Vec<(u16, OutboundUdp)>,
}

/// Rebuild `io.pollfds` / `io.conn_ports` for this iteration: the
/// wake pipe, then the shared TCP listen fds, then this vCPU's
/// outbound-UDP NAT fds, then its assigned TCP conn fds. Returns the
/// slot layout the post-`poll` phases index with.
fn build_pollfds(io: &mut IoState, shared: &WorkerShared, listens: &[TcpListen]) -> PollLayout {
    io.pollfds.clear();
    io.conn_ports.clear();
    io.pollfds.push(libc::pollfd {
        fd: io.wake_pipe_read,
        events: libc::POLLIN,
        revents: 0,
    });
    io.conn_ports.push(0);
    // UDP fds are no longer polled per-vCPU; the dedicated UDP
    // listener thread owns recvfrom and forwards inbound frames to
    // each vCPU's `forwarded_rx` mailbox (drained at the top of
    // this poll loop).
    let listen_slot_start = io.pollfds.len();
    for l in listens {
        io.pollfds.push(libc::pollfd {
            fd: l.fd,
            events: libc::POLLIN,
            revents: 0,
        });
        io.conn_ports.push(0);
    }
    // Outbound UDP NAT fds — guest-initiated UDP flows we forwarded
    // to the host's loopback. Reply datagrams arrive here and we
    // synthesise a UDP frame back into the guest's RX queue.
    // `conn_ports` records the GUEST src_port so the reply frame
    // can carry the right (src=last_dst, dst=guest_src) addressing.
    let outbound_slot_start = io.pollfds.len();
    let outbound_drain: Vec<(u16, OutboundUdp)> = io
        .outbound_udp
        .iter()
        .map(|(&port, &o)| (port, o))
        .collect();
    for (gport, o) in &outbound_drain {
        io.pollfds.push(libc::pollfd {
            fd: o.fd,
            events: libc::POLLIN,
            revents: 0,
        });
        io.conn_ports.push(*gport);
    }
    let fixed_slots = io.pollfds.len();
    {
        let conns = shared.conns.lock().unwrap();
        for c in conns.values() {
            io.pollfds.push(libc::pollfd {
                fd: if c.host_fd >= 0 && c.state < ConnState::Closed {
                    c.host_fd
                } else {
                    -1
                },
                events: libc::POLLIN,
                revents: 0,
            });
            io.conn_ports.push(c.src_port);
        }
    }
    PollLayout {
        listen_slot_start,
        outbound_slot_start,
        fixed_slots,
        outbound_drain,
    }
}

/// Inline-accept the backlog on every shared TCP listen fd that fired
/// POLLIN. Every vCPU polls the same listen fds; `accept` is non-
/// blocking and thread-safe, so racing vCPUs each win exactly one
/// pending SYN and the rest see `EAGAIN`. Each accept allocates a
/// guest-visible pseudo-ephemeral source port, queues a synthetic SYN
/// onto this vCPU's `tx_replies`, and inserts the `ProxyConn` into
/// this vCPU's own `WORKERS[id].conns` — no cross-vCPU contention.
/// v4 ports are flow-hash-aware so the conn stays on one guest core;
/// v6 takes the next free port.
fn accept_listen_backlog(
    io: &mut IoState,
    shared: &WorkerShared,
    qsnap: &virtio::QueueSnapshot,
    cpu_count: usize,
    listens: &[TcpListen],
    listen_slot_start: usize,
    any_injected: &mut bool,
) {
    // `single_queue` is derived rather than passed — keeps the arg
    // count at clippy's `too_many_arguments` ceiling of 7.
    let single_queue = cpu_count <= 1;
    if !listens.is_empty() {
        let mut accepted_any = false;
        for (i, listen) in listens.iter().enumerate() {
            if io.pollfds[listen_slot_start + i].revents & libc::POLLIN == 0 {
                continue;
            }
            loop {
                let client_fd =
                    unsafe { libc::accept(listen.fd, std::ptr::null_mut(), std::ptr::null_mut()) };
                if client_fd < 0 {
                    break;
                }
                unsafe {
                    libc::fcntl(client_fd, libc::F_SETFL, libc::O_NONBLOCK);
                    let one: i32 = 1;
                    libc::setsockopt(
                        client_fd,
                        libc::IPPROTO_TCP,
                        libc::TCP_NODELAY,
                        &one as *const _ as *const _,
                        4,
                    );
                    // Big send/recv buffers so a bursty guest response
                    // (the server emitting a multi-segment body back to
                    // back, filling its window) doesn't fill the host
                    // socket's send buffer mid-burst. `handle_tcp`'s
                    // best-effort guest→host write drops on EAGAIN
                    // (`guest_tx.rs`), so a too-small SO_SNDBUF turned a
                    // large single-conn download into an intermittent
                    // truncation — only on the toy proxy, never on a real
                    // NIC.
                    //
                    // Size it off the kernel ceiling: macOS/BSD's
                    // `setsockopt(SO_SNDBUF)` *rejects* (EINVAL) a value
                    // above `kern.ipc.maxsockbuf` rather than clamping, so
                    // a fixed 16 MiB silently failed on the default 8 MiB
                    // ceiling and left the buffer at the 128 KiB default —
                    // which passed 256 KiB transfers but dropped 1 MiB
                    // ones. Request 3/4 of the ceiling (BSD's effective
                    // `sb_max_adj` is ~0.93×, so stay clear of it); fall
                    // back to 2 MiB if the sysctl is unavailable.
                    let mut maxsockbuf: i32 = 0;
                    let mut msz = std::mem::size_of::<i32>();
                    let have_max = libc::sysctlbyname(
                        b"kern.ipc.maxsockbuf\0".as_ptr() as *const _,
                        &mut maxsockbuf as *mut _ as *mut _,
                        &mut msz,
                        std::ptr::null_mut(),
                        0,
                    ) == 0
                        && maxsockbuf > 0;
                    let bufsz: i32 = if have_max {
                        (maxsockbuf / 4 * 3).min(16 * 1024 * 1024)
                    } else {
                        2 * 1024 * 1024
                    };
                    libc::setsockopt(
                        client_fd,
                        libc::SOL_SOCKET,
                        libc::SO_SNDBUF,
                        &bufsz as *const _ as *const _,
                        4,
                    );
                    libc::setsockopt(
                        client_fd,
                        libc::SOL_SOCKET,
                        libc::SO_RCVBUF,
                        &bufsz as *const _ as *const _,
                        4,
                    );
                }
                // Flow-hash-aware src_port selection (v4 only): pick
                // a port whose 4-tuple hashes to the current vCPU's
                // bucket under the guest's `net/lib.rs::flow_hash`.
                // That keeps the conn on a single core end-to-end —
                // without it, ~(cpu_count-1)/cpu_count of accepted
                // connections would land on one guest core and
                // bounce to another via the SPSC `rx_inbox` on
                // every packet. The guest's v6 receive path doesn't
                // run flow_hash today (single-core dispatch under
                // Tier 1 is on the v4 fast path only), so v6
                // accepts skip the loop and grab the next free port.
                let src_port = match listen.family {
                    IpFamily::V4 => alloc_src_port_for_vcpu(io.id, cpu_count, listen.guest_port),
                    IpFamily::V6 => alloc_src_port(),
                };
                let frame = build_tcp_reply(
                    listen.family,
                    src_port,
                    listen.guest_port,
                    1000,
                    0,
                    0x02,
                    &[],
                );
                shared.tx_replies.lock().unwrap().push_back(frame);
                shared.conns.lock().unwrap().insert(
                    src_port,
                    ProxyConn {
                        host_fd: client_fd,
                        src_port,
                        guest_port: listen.guest_port,
                        my_seq: 1001,
                        peer_ack: 0,
                        state: ConnState::SynSent,
                        pending: Vec::new(),
                        family: listen.family,
                    },
                );
                accepted_any = true;
            }
        }
        if accepted_any {
            // Drain the SYN frame(s) we just queued into the guest
            // RX ring immediately so they don't wait a full poll
            // iteration before reaching the guest. Same pattern as
            // the top-of-loop drain but only runs if we actually
            // accepted something.
            let mut replies = shared.tx_replies.lock().unwrap();
            while let Some(f) = replies.pop_front() {
                if !qsnap.ready || !inject_frame(f.as_slice(), qsnap, &mut io.rx_last) {
                    replies.push_front(f);
                    break;
                }
                *any_injected = true;
            }
            drop(replies);
            if *any_injected {
                unsafe {
                    core::arch::asm!("dsb sy", options(nostack));
                }
                if single_queue {
                    unsafe {
                        hvf::hv_gic_set_spi(35, true);
                        hvf::hv_gic_set_spi(35, false);
                    }
                }
            }
        }
    }

}

/// Drain outbound-UDP NAT replies: for each guest-initiated UDP flow
/// whose host fd fired POLLIN, `recv` until `EAGAIN` and queue a UDP
/// reply frame (addressed from the flow's saved `last_dst_*` so the
/// guest's stack accepts it) onto `tx_replies` for injection next
/// iteration.
fn drain_outbound_udp(
    io: &IoState,
    shared: &WorkerShared,
    outbound_drain: &[(u16, OutboundUdp)],
    outbound_slot_start: usize,
    any_injected: &mut bool,
) {
    if !outbound_drain.is_empty() {
        for (i, (gport, o)) in outbound_drain.iter().enumerate() {
            if io.pollfds[outbound_slot_start + i].revents & (libc::POLLIN | libc::POLLHUP) == 0 {
                continue;
            }
            loop {
                let mut buf = [0u8; 1500];
                let n = unsafe { libc::recv(o.fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
                if n <= 0 {
                    break;
                }
                let payload = &buf[..n as usize];
                let frame = build_udp_frame_in(
                    &io.guest_mac,
                    o.last_dst_ip,
                    o.last_dst_port,
                    *gport,
                    payload,
                );
                shared.tx_replies.lock().unwrap().push_back(frame);
                *any_injected = true;
            }
        }
    }

}

/// Zero-copy RX from this vCPU's established TCP conns. For each conn
/// fd that fired POLLIN, read the host payload straight into the
/// guest RX descriptor, stamp Eth/IP/TCP headers around it, and
/// publish the used-ring entry; on host EOF synthesise a FIN+ACK and
/// close the host fd. When the RX queue is not yet ready the data is
/// buffered into the conn's `pending` instead.
fn drain_conn_rx(
    io: &mut IoState,
    shared: &WorkerShared,
    qsnap: &virtio::QueueSnapshot,
    single_queue: bool,
    fixed_slots: usize,
    any_injected: &mut bool,
) {
    const HDR_LEN_V4: usize = VIRTIO_NET_HDR_SIZE + 14 + 20 + 20;
    const HDR_LEN_V6: usize = VIRTIO_NET_HDR_SIZE + 14 + 40 + 20;
    const MAX_PAYLOAD_V4: usize = 1460;
    const MAX_PAYLOAD_V6: usize = 1440;
    struct ConnSnap {
        port: u16,
        guest_port: u16,
        fd: i32,
        seq: u32,
        ack: u32,
        family: IpFamily,
    }

    if qsnap.ready {
        let snaps: Vec<ConnSnap> = {
            let conns = shared.conns.lock().unwrap();
            (fixed_slots..io.pollfds.len())
                .filter(|&i| io.pollfds[i].revents & (libc::POLLIN | libc::POLLHUP) != 0)
                .filter_map(|i| {
                    let port = io.conn_ports[i];
                    conns.get(&port).and_then(|c| {
                        if c.host_fd >= 0 && c.state == ConnState::Established {
                            Some(ConnSnap {
                                port,
                                guest_port: c.guest_port,
                                fd: c.host_fd,
                                seq: c.my_seq,
                                ack: c.peer_ack,
                                family: c.family,
                            })
                        } else {
                            None
                        }
                    })
                })
                .collect()
        };

        struct RxResult {
            port: u16,
            seq_advance: u32,
            eof: bool,
        }
        let mut results: Vec<RxResult> = Vec::new();
        let mut injected = false;

        for cs in &snaps {
            if !qsnap.ready {
                continue;
            }

            let avail_idx = unsafe {
                core::ptr::read_volatile(qsnap.gpa_to_host(qsnap.avail_addr + 2) as *const u16)
            };
            if io.rx_last == avail_idx {
                continue;
            }
            let ring_idx = io.rx_last & (qsnap.qsize - 1);
            let desc_idx = unsafe {
                core::ptr::read_volatile(
                    qsnap.gpa_to_host(qsnap.avail_addr + 4 + ring_idx as u64 * 2) as *const u16,
                )
            };
            let buf_addr = unsafe {
                core::ptr::read_unaligned(
                    qsnap.gpa_to_host(qsnap.desc_addr + desc_idx as u64 * 16) as *const u64
                )
            };
            let guest_buf = qsnap.gpa_to_host(buf_addr);

            let (hdr_len, max_payload) = match cs.family {
                IpFamily::V4 => (HDR_LEN_V4, MAX_PAYLOAD_V4),
                IpFamily::V6 => (HDR_LEN_V6, MAX_PAYLOAD_V6),
            };
            let payload_ptr = unsafe { guest_buf.add(hdr_len) };
            let n = unsafe { libc::read(cs.fd, payload_ptr as *mut _, max_payload) };
            if n <= 0 {
                if n == 0 {
                    results.push(RxResult {
                        port: cs.port,
                        seq_advance: 0,
                        eof: true,
                    });
                }
                continue;
            }
            let payload_len = n as usize;

            let addrs = match cs.family {
                IpFamily::V4 => IpAddrPair::V4 {
                    src: GW_IP,
                    dst: VM_IP,
                },
                IpFamily::V6 => IpAddrPair::V6 {
                    src: GW_IPV6,
                    dst: VM_IPV6,
                },
            };
            let total = write_tcp_frame_around_payload(
                guest_buf,
                &GUEST_MAC,
                &addrs,
                &TcpFrameSpec {
                    src_port: cs.port,
                    dst_port: cs.guest_port,
                    seq: cs.seq,
                    ack: cs.ack,
                    flags: 0x18,
                },
                payload_len,
            );

            let used_idx = io.rx_last;
            unsafe {
                let entry = qsnap
                    .gpa_to_host(qsnap.used_addr + 4 + (used_idx & (qsnap.qsize - 1)) as u64 * 8);
                core::ptr::write_unaligned(entry as *mut u32, desc_idx as u32);
                core::ptr::write_unaligned(entry.add(4) as *mut u32, total as u32);
                core::ptr::write_volatile(
                    qsnap.gpa_to_host(qsnap.used_addr + 2) as *mut u16,
                    used_idx.wrapping_add(1),
                );
            }
            io.rx_last = io.rx_last.wrapping_add(1);
            results.push(RxResult {
                port: cs.port,
                seq_advance: payload_len as u32,
                eof: false,
            });
            injected = true;
        }

        if !results.is_empty() {
            let mut conns = shared.conns.lock().unwrap();
            for r in &results {
                if let Some(c) = conns.get_mut(&r.port) {
                    if r.eof {
                        let frame = build_tcp_reply(
                            c.family,
                            c.src_port,
                            c.guest_port,
                            c.my_seq,
                            c.peer_ack,
                            0x11,
                            &[],
                        );
                        c.my_seq = c.my_seq.wrapping_add(1);
                        // Half-closed: we have sent our FIN, but the
                        // guest still owes us its FIN. Stay in FinWait
                        // (not Closed) so `handle_tcp` acknowledges
                        // that FIN when it arrives and the guest's
                        // LastAck completes instead of stranding.
                        c.state = ConnState::FinWait;
                        // Drop the host fd now so the kernel socket
                        // leaves CLOSE_WAIT instead of leaking until
                        // process exit.
                        unsafe {
                            libc::close(c.host_fd);
                        }
                        c.host_fd = -1;
                        inject_frame(frame.as_slice(), qsnap, &mut io.rx_last);
                        injected = true;
                    } else {
                        c.my_seq = c.my_seq.wrapping_add(r.seq_advance);
                    }
                }
            }
        }

        if injected {
            unsafe {
                core::arch::asm!("dsb sy", options(nostack));
            }
            if single_queue {
                unsafe {
                    hvf::hv_gic_set_spi(35, true);
                    hvf::hv_gic_set_spi(35, false);
                }
            }
            *any_injected = true;
        }
    } else {
        // RX queue not ready — buffer data in pending.
        let mut conns = shared.conns.lock().unwrap();
        for i in fixed_slots..io.pollfds.len() {
            if io.pollfds[i].revents & (libc::POLLIN | libc::POLLHUP) == 0 {
                continue;
            }
            let port = io.conn_ports[i];
            if let Some(c) = conns.get_mut(&port) {
                if c.host_fd < 0 {
                    continue;
                }
                let n = unsafe {
                    libc::read(
                        c.host_fd,
                        io.read_buf.as_mut_ptr() as *mut _,
                        io.read_buf.len(),
                    )
                };
                if n > 0 {
                    c.pending.extend_from_slice(&io.read_buf[..n as usize]);
                }
            }
        }
    }

}

fn poll_worker_iteration(io: &mut IoState, cpu_count: usize, timeout_ms: i32) -> bool {
    let id = io.id;
    let single_queue = cpu_count <= 1;
    let shared = worker_shared(id);

    // First call: worker 0 broadcasts a gratuitous ARP so the host
    // learns our MAC. Done here (instead of `start()`) so the frame is
    // injected from the vCPU thread that owns the queue.
    if !io.primed {
        if id == 0 {
            shared
                .tx_replies
                .lock()
                .unwrap()
                .push_back(build_grat_arp_frame(&io.guest_mac));
        }
        io.primed = true;
    }

    // In multi-queue mode, each worker's queue pair is (id*2, id*2+1).
    // In single-queue mode, there's one shared queue pair at (0, 1).
    let qsnap = if single_queue {
        virtio::rx_queue_snapshot()
    } else {
        virtio::queue_snapshot(id * 2)
    };

    // RX injection — staged replies, cross-vCPU forwards, and the
    // backlog buffered for conns that have since become Established.
    let mut any_injected = false;
    any_injected |= drain_tx_replies(io, shared, &qsnap, single_queue);
    any_injected |= drain_forwarded_rx(io, shared, &qsnap, single_queue);
    any_injected |= flush_established_pending(io, shared, &qsnap, single_queue);

    // Rebuild the pollfd set (wake pipe / TCP listens / outbound-UDP
    // NAT fds / assigned conn fds) and poll it. `conn_ports` is kept
    // parallel to `pollfds`, valid only in the conn range.
    let listens: &[TcpListen] = LISTENS.get().map(|v| v.as_slice()).unwrap_or(&[]);
    let layout = build_pollfds(io, shared, listens);

    let ready = unsafe { libc::poll(io.pollfds.as_mut_ptr(), io.pollfds.len() as u32, timeout_ms) };
    if ready <= 0 {
        return any_injected;
    }

    // ── Drain wake pipe doorbell ───────────────────────────────────
    // The bytes are signals from another thread (the accept thread, or
    // the stdin reader after delivering a Ctrl-C byte through virtio-
    // console). The actual work (new conn, RX queue update) was done
    // before the doorbell — we drain so it doesn't refire on the next
    // poll, and flag `any_injected=true` so the yield-handler caller
    // can break out and let the guest observe whatever just landed.
    if io.pollfds[0].revents & libc::POLLIN != 0 {
        let mut tmp = [0u8; 64];
        loop {
            let n = unsafe { libc::read(io.wake_pipe_read, tmp.as_mut_ptr() as *mut _, tmp.len()) };
            if n <= 0 {
                break;
            }
        }
        any_injected = true;
    }

    // ── Post-poll work: accept new conns, drain outbound-UDP NAT
    //    replies, then pull RX from this vCPU's established conns.
    accept_listen_backlog(
        io,
        shared,
        &qsnap,
        cpu_count,
        listens,
        layout.listen_slot_start,
        &mut any_injected,
    );
    drain_outbound_udp(
        io,
        shared,
        &layout.outbound_drain,
        layout.outbound_slot_start,
        &mut any_injected,
    );
    drain_conn_rx(
        io,
        shared,
        &qsnap,
        single_queue,
        layout.fixed_slots,
        &mut any_injected,
    );

    // Periodic closed-conn cleanup.
    io.cleanup_ctr = io.cleanup_ctr.wrapping_add(1);
    if io.cleanup_ctr.is_multiple_of(1000) {
        let mut conns = shared.conns.lock().unwrap();
        conns.retain(|_, c| c.state < ConnState::Closed || c.host_fd >= 0);
    }

    any_injected
}

/// Allocate the next guest-visible pseudo-ephemeral source port.
/// Wraps in [40000, 60000); used to give each accepted TCP conn a
/// unique 5-tuple from the guest's point of view.
fn alloc_src_port() -> u16 {
    let mut p = NEXT_PROXY_SRC_PORT.fetch_add(1, Ordering::Relaxed);
    if p >= 60000 {
        let _ = NEXT_PROXY_SRC_PORT.compare_exchange(
            p + 1,
            40000,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        p = NEXT_PROXY_SRC_PORT.fetch_add(1, Ordering::Relaxed);
    }
    p
}

/// Flow-hash a synthetic 4-tuple the same way the guest does in
/// `net/lib.rs::flow_hash`. The guest uses this to decide which
/// core owns a given TCP connection's state, so mirroring the
/// computation here lets us pick an ephemeral src_port at accept
/// time whose hash lands on the *current* vCPU. That keeps the
/// packet on the same core end-to-end: this vCPU injects the SYN
/// into its own RX queue pair, the guest's vCPU N receives it,
/// runs the same flow hash, gets N, and processes the packet
/// inline instead of pushing it to another core's SPSC `rx_inbox`.
///
/// Both builds are little-endian on our target hardware
/// (aarch64-apple-darwin for the runner, aarch64-unknown-none for
/// the guest), so `u32::from_le_bytes` matches the raw byte-read
/// the guest does on its `Ipv4Header` struct field. Keep this in
/// sync with `net/lib.rs::flow_hash` — the whole point of mirroring
/// it is that the two have to produce the same answer for the
/// same 4-tuple.
fn flow_hash_for_guest(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    num_cores: u32,
) -> u32 {
    let sip = u32::from_le_bytes(src_ip);
    let dip = u32::from_le_bytes(dst_ip);
    let mut h: u32 = 2166136261; // FNV offset basis
    h ^= sip;
    h = h.wrapping_mul(16777619);
    h ^= dip;
    h = h.wrapping_mul(16777619);
    h ^= src_port as u32;
    h = h.wrapping_mul(16777619);
    h ^= dst_port as u32;
    h = h.wrapping_mul(16777619);
    // Murmur3 fmix32.
    h ^= h >> 16;
    h = h.wrapping_mul(0x85ebca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2ae35);
    h ^= h >> 16;
    h % num_cores
}

/// Allocate an ephemeral src_port whose flow hash lands on
/// `target_vcpu` for the given 4-tuple shape. Loops over
/// candidates from `NEXT_PROXY_SRC_PORT` until it finds a match or
/// exhausts a bounded budget (4 × cpu_count ≈ the expected number
/// of tries for a uniform hash over `cpu_count` buckets, with
/// headroom). Falls back to a plain `alloc_src_port()` on budget
/// exhaustion so the accept never stalls — the odd mis-hashed
/// connection just pays the SPSC `rx_inbox` cross-core hop on the
/// guest side, same as pre-Option-2 behaviour.
///
/// For `cpu_count == 1` there's only one bucket and every port
/// matches; the loop body finishes on the first try.
fn alloc_src_port_for_vcpu(target_vcpu: usize, cpu_count: usize, dst_port: u16) -> u16 {
    if cpu_count <= 1 {
        return alloc_src_port();
    }
    let ncores = cpu_count as u32;
    let budget = cpu_count * 4;
    for _ in 0..budget {
        let p = alloc_src_port();
        let bucket = flow_hash_for_guest(GW_IP, VM_IP, p, dst_port, ncores);
        if bucket as usize == target_vcpu {
            return p;
        }
    }
    alloc_src_port()
}

// Drain a UDP relay sibling fd owned by this worker, injecting frames
// into the worker's own RX queue. Because each worker owns its own
// sibling fd (distributed by SO_REUSEPORT hashing at bind time), there's
// no cross-worker software RSS needed — the kernel already routed the
// datagram to us.
