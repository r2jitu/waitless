// tools/hvf-runner/src/userspace_net.rs
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
use std::sync::{Mutex, OnceLock};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};

use crate::hvf;
use crate::virtio;

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
    0xfe, 0x80, 0, 0, 0, 0, 0, 0,
    GW_MAC[0] ^ 0x02, GW_MAC[1], GW_MAC[2],
    0xff, 0xfe,
    GW_MAC[3], GW_MAC[4], GW_MAC[5],
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
    Closed = 2,
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
    /// by the vCPU in `handle_udp` when the guest sends a reply.
    udp_clients: Mutex<HashMap<(u16, u16), libc::sockaddr_in>>,
    /// IPv6 counterpart to `udp_clients`. Same `(guest_port,
    /// client_ephemeral_port)` key, value is `sockaddr_in6` so the
    /// TX-side reply in `handle_udp_v6` can `sendto` the original
    /// peer over IPv6.
    udp_clients_v6: Mutex<HashMap<(u16, u16), libc::sockaddr_in6>>,
}

impl WorkerShared {
    fn new() -> Self {
        Self {
            conns: Mutex::new(HashMap::new()),
            tx_replies: Mutex::new(VecDeque::new()),
            udp_clients_v6: Mutex::new(HashMap::new()),
            udp_clients: Mutex::new(HashMap::new()),
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
    Ok(WakePipe { read_fd: fds[0], write_fd: fds[1] })
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
            unsafe { libc::write(p.write_fd, buf.as_ptr() as *const _, 1); }
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
/// threads (handle_tcp/handle_udp/handle_guest_tx) where the current
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
/// `bind_listen` for AF_INET and (best-effort) `bind_listen_v6` for
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

/// One UDP-relay sibling, scoped to a single vCPU's IoState. The
/// enclosing relay opens `cpu_count` SO_REUSEPORT-bound siblings at
/// `start()` time; vCPU `N` owns sibling `N`, and `UDP_RELAYS` below
/// keeps a flat `Vec<i32>` so the TX-side `handle_udp` can still look
/// up "this vCPU's sibling" when the guest sends a reply.
///
/// `family` distinguishes the v4 sibling (binds 127.0.0.1) from the
/// v6 sibling (binds ::1). Both fds for a given guest_port are
/// added to every vCPU's pollfds; on read we dispatch to
/// `handle_udp_rx` (v4) or `handle_udp_rx_v6` (v6) accordingly.
#[derive(Clone, Copy)]
struct UdpRelay {
    fd: i32,
    guest_port: u16,
    family: IpFamily,
}

/// IP family tag shared by `UdpRelay`, `TcpListen`, and `ProxyConn`.
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
                buf[9] = 6;  // protocol = TCP
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
                buf[6] = 6;  // next_header = TCP
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
    /// UDP relay sockets owned by this vCPU — one per `-p udp:H:G`
    /// mapping. Each entry holds exactly one fd (the sibling the
    /// kernel hands this vCPU via SO_REUSEPORT distribution).
    udps: Vec<UdpRelay>,
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
fn bind_listen(host_port: u16) -> Result<i32, String> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 { return Err(format!("tcp socket(): {}", std::io::Error::last_os_error())); }
        let one: i32 = 1;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR,
                         &one as *const _ as *const _, 4);
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as u8;
        addr.sin_port = host_port.to_be();
        addr.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();
        if libc::bind(fd, &addr as *const _ as *const _, std::mem::size_of_val(&addr) as u32) < 0 {
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

/// IPv6 sibling of `bind_listen`. Same shape but AF_INET6 +
/// `IPV6_V6ONLY=1` bound to `[::1]:host_port`, so v4 and v6
/// listeners on the same host port stay disjoint (no
/// `::ffff:1.2.3.4` mapped weirdness on accept). Best-effort: a
/// failure here just means v6 traffic doesn't reach the guest
/// over this mapping; the v4 listener stays up.
fn bind_listen_v6(host_port: u16) -> Result<i32, String> {
    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(format!("tcp v6 socket(): {}", std::io::Error::last_os_error()));
        }
        let one: i32 = 1;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR,
                         &one as *const _ as *const _, 4);
        libc::setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY,
                         &one as *const _ as *const _, 4);
        let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
        addr.sin6_family = libc::AF_INET6 as u8;
        addr.sin6_port = host_port.to_be();
        // `s6_addr[15] = 1` is `::1`, mirroring the v4 `127.0.0.1`
        // bind so non-loopback v6 traffic doesn't accidentally hit
        // the relay.
        addr.sin6_addr.s6_addr[15] = 1;
        if libc::bind(fd, &addr as *const _ as *const _, std::mem::size_of_val(&addr) as u32) < 0 {
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
fn open_udp_sibling(host_port: u16) -> Result<i32, String> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 { return Err(format!("udp socket(): {}", std::io::Error::last_os_error())); }
        let one: i32 = 1;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR,
                         &one as *const _ as *const _, 4);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT,
                         &one as *const _ as *const _, 4);
        // Big buffers so bursty UDP doesn't drop at the host kernel.
        let bufsz: i32 = 16 * 1024 * 1024;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF,
                         &bufsz as *const _ as *const _, 4);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF,
                         &bufsz as *const _ as *const _, 4);
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as u8;
        addr.sin_port = host_port.to_be();
        addr.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();
        if libc::bind(fd, &addr as *const _ as *const _, std::mem::size_of_val(&addr) as u32) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(format!("udp bind({host_port}): {e}"));
        }
        libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
        Ok(fd)
    }
}

/// IPv6 sibling of `open_udp_sibling`. Binds to `[::1]:host_port`
/// with `IPV6_V6ONLY=1` so v4 traffic still goes to the AF_INET
/// sibling — keeps the receive-path code paths cleanly separated
/// (v4 sees `sockaddr_in`, v6 sees `sockaddr_in6`, no
/// `::ffff:1.2.3.4` mapped weirdness).
fn open_udp_sibling_v6(host_port: u16) -> Result<i32, String> {
    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(format!("udp v6 socket(): {}", std::io::Error::last_os_error()));
        }
        let one: i32 = 1;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR,
                         &one as *const _ as *const _, 4);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT,
                         &one as *const _ as *const _, 4);
        libc::setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY,
                         &one as *const _ as *const _, 4);
        let bufsz: i32 = 16 * 1024 * 1024;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF,
                         &bufsz as *const _ as *const _, 4);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF,
                         &bufsz as *const _ as *const _, 4);
        let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
        addr.sin6_family = libc::AF_INET6 as u8;
        addr.sin6_port = host_port.to_be();
        // Bind to ::1 (loopback) so non-loopback traffic doesn't
        // accidentally hit the relay; mirrors the v4 `127.0.0.1`
        // bind. `s6_addr[15] = 1` is `::1`.
        addr.sin6_addr.s6_addr[15] = 1;
        if libc::bind(fd, &addr as *const _ as *const _, std::mem::size_of_val(&addr) as u32) < 0 {
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
    let mut per_worker_udps: Vec<Vec<UdpRelay>> =
        (0..cpu_count).map(|_| Vec::new()).collect();
    let mut relay_table: Vec<UdpRelayFds> = Vec::new();
    let mut relay_table_v6: Vec<UdpRelayFds> = Vec::new();

    for m in mappings {
        match m.proto {
            Proto::Tcp => {
                let fd = bind_listen(m.host)?;
                listens.push(TcpListen { fd, guest_port: m.guest, family: IpFamily::V4 });
                // IPv6 sibling on the same host port — failure is
                // non-fatal (e.g. ::1 not configured): we keep the
                // v4 listener and the mapping just doesn't carry
                // v6 traffic into the guest.
                match bind_listen_v6(m.host) {
                    Ok(fd6) => listens.push(TcpListen {
                        fd: fd6, guest_port: m.guest, family: IpFamily::V6,
                    }),
                    Err(e) => eprintln!("  warning: {e}"),
                }
            }
            Proto::Udp => {
                match open_udp_sibling(m.host) {
                    Ok(fd) => {
                        for worker_id in 0..cpu_count {
                            per_worker_udps[worker_id].push(UdpRelay {
                                fd, guest_port: m.guest, family: IpFamily::V4,
                            });
                        }
                        let fds = vec![fd; cpu_count.max(1)];
                        relay_table.push(UdpRelayFds { guest_port: m.guest, fds });
                    }
                    Err(e) => eprintln!("  warning: {e}"),
                }
                // IPv6 sibling on the same host port — bind failure
                // here is also non-fatal (e.g. ::1 not configured),
                // we just log and continue with v4-only relay.
                match open_udp_sibling_v6(m.host) {
                    Ok(fd) => {
                        for worker_id in 0..cpu_count {
                            per_worker_udps[worker_id].push(UdpRelay {
                                fd, guest_port: m.guest, family: IpFamily::V6,
                            });
                        }
                        let fds = vec![fd; cpu_count.max(1)];
                        relay_table_v6.push(UdpRelayFds { guest_port: m.guest, fds });
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
    for id in 0..cpu_count {
        let udps = std::mem::take(&mut per_worker_udps[id]);
        vcpu_ios.push(Mutex::new(IoState {
            id,
            udps,
            outbound_udp: HashMap::new(),
            wake_pipe_read: wake_reads[id],
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
        eprintln!("  Benchmark:  wrk -t1 -c1 -d10s http://localhost:{}/health", first_tcp.host);
    }
    eprintln!();
    Ok(mac)
}

// Per-vCPU thread-local: the id of the vCPU whose TX queue notify
// we are currently handling. Read by `handle_udp` to pick the right
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
    if !tx.ready { return; }

    // Map queue_idx to a slot in the per-thread last array (TX queues: 1,3,5,7,... → slots 0..8)
    let slot = (queue_idx / 2) as usize;
    if slot >= 9 { return; }

    // Remember which vCPU we're processing for — `handle_udp` uses it
    // to pick its per-vCPU TX socket.
    CURRENT_VCPU.with(|c| c.set(slot));

    let avail_idx = unsafe {
        core::ptr::read_volatile(tx.gpa_to_host(tx.avail_addr + 2) as *const u16)
    };
    let mut lasts = TX_LAST_MAP.with(|c| c.get());
    let mut last = lasts[slot];
    if last == avail_idx { return; }

    while last != avail_idx {
        let ring_idx = last & (tx.qsize - 1);
        let desc_idx = unsafe {
            core::ptr::read_volatile(
                tx.gpa_to_host(tx.avail_addr + 4 + ring_idx as u64 * 2) as *const u16)
        };
        let (addr, len) = unsafe {
            let dp = tx.gpa_to_host(tx.desc_addr + desc_idx as u64 * 16);
            (core::ptr::read_unaligned(dp as *const u64),
             core::ptr::read_unaligned(dp.add(8) as *const u32) as usize)
        };
        if len > VIRTIO_NET_HDR_SIZE {
            let frame = unsafe {
                std::slice::from_raw_parts(
                    tx.gpa_to_host(addr).add(VIRTIO_NET_HDR_SIZE),
                    len - VIRTIO_NET_HDR_SIZE)
            };
            handle_guest_tx(frame);
        }
        // Update TX used ring (host-side tracking via TX_LAST).
        let used_idx = last; // host tracks its own used_idx, not guest RAM
        unsafe {
            let entry = tx.gpa_to_host(tx.used_addr + 4 + (used_idx & (tx.qsize - 1)) as u64 * 8);
            core::ptr::write_unaligned(entry as *mut u32, desc_idx as u32);
            core::ptr::write_unaligned(entry.add(4) as *mut u32, len as u32);
            core::ptr::write_volatile(tx.gpa_to_host(tx.used_addr + 2) as *mut u16,
                used_idx.wrapping_add(1));
        }
        last = last.wrapping_add(1);
    }
    lasts[slot] = last;
    TX_LAST_MAP.with(|c| c.set(lasts));
    unsafe { core::arch::asm!("dsb sy", options(nostack)); }
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
    if vcpu_id >= ios.len() { return false; }
    let cpu_count = CPU_COUNT.load(Ordering::Acquire);
    let mut io = ios[vcpu_id].lock().unwrap();
    poll_worker_iteration(&mut io, cpu_count, timeout_ms)
}

fn poll_worker_iteration(
    io: &mut IoState,
    cpu_count: usize,
    timeout_ms: i32,
) -> bool {
    let id = io.id;
    let single_queue = cpu_count <= 1;
    let shared = worker_shared(id);

    // First call: worker 0 broadcasts a gratuitous ARP so the host
    // learns our MAC. Done here (instead of `start()`) so the frame is
    // injected from the vCPU thread that owns the queue.
    if !io.primed {
        if id == 0 {
            shared.tx_replies.lock().unwrap().push_back(build_grat_arp_frame(&io.guest_mac));
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

    let mut any_injected = false;

    // ── Drain reply frames staged by handle_tcp/handle_udp/handle_arp ──
    {
        let mut replies = shared.tx_replies.lock().unwrap();
        let mut any = false;
        while let Some(f) = replies.pop_front() {
            if !qsnap.ready || !inject_frame(f.as_slice(), &qsnap, &mut io.rx_last) {
                replies.push_front(f);
                break;
            }
            any = true;
        }
        drop(replies);
        if any {
            unsafe { core::arch::asm!("dsb sy", options(nostack)); }
            if single_queue {
                unsafe { hvf::hv_gic_set_spi(35, true); hvf::hv_gic_set_spi(35, false); }
            }
            any_injected = true;
        }
    }

    // ── Flush pending data for conns that just became ESTABLISHED ──
    {
        let mut conns = shared.conns.lock().unwrap();
        let mut flushed = false;
        for c in conns.values_mut() {
            if c.state == ConnState::Established && !c.pending.is_empty() && qsnap.ready {
                let p = std::mem::take(&mut c.pending);
                inject_data_frames(c, &p, &GUEST_MAC, &qsnap, &mut io.rx_last, &mut io.frame_buf);
                flushed = true;
            }
        }
        drop(conns);
        if flushed {
            unsafe { core::arch::asm!("dsb sy", options(nostack)); }
            if single_queue {
                unsafe { hvf::hv_gic_set_spi(35, true); hvf::hv_gic_set_spi(35, false); }
            }
            any_injected = true;
        }
    }

    // ── Build pollfds: wake pipe, UDP siblings, TCP listens, conns ─
    // Slot 0 is the wake pipe; then UDP siblings; then shared TCP
    // listen fds (polled by every vCPU so inline accept wins
    // first-come-first-served); then this vCPU's assigned TCP conn
    // fds. `conn_ports` is parallel to `pollfds` with a 0 entry in
    // every non-conn slot; only the conn range carries valid ports.
    io.pollfds.clear();
    io.conn_ports.clear();
    io.pollfds.push(libc::pollfd {
        fd: io.wake_pipe_read, events: libc::POLLIN, revents: 0,
    });
    io.conn_ports.push(0);
    let udp_slot_start = io.pollfds.len();
    for u in &io.udps {
        io.pollfds.push(libc::pollfd { fd: u.fd, events: libc::POLLIN, revents: 0 });
        io.conn_ports.push(0);
    }
    let listen_slot_start = io.pollfds.len();
    let listens: &[TcpListen] = LISTENS.get().map(|v| v.as_slice()).unwrap_or(&[]);
    for l in listens {
        io.pollfds.push(libc::pollfd { fd: l.fd, events: libc::POLLIN, revents: 0 });
        io.conn_ports.push(0);
    }
    // Outbound UDP NAT fds — guest-initiated UDP flows we forwarded
    // to the host's loopback. Reply datagrams arrive here and we
    // synthesise a UDP frame back into the guest's RX queue.
    // `conn_ports` records the GUEST src_port so the reply frame
    // can carry the right (src=last_dst, dst=guest_src) addressing.
    let outbound_slot_start = io.pollfds.len();
    let outbound_drain: Vec<(u16, OutboundUdp)> = io.outbound_udp.iter()
        .map(|(&port, &o)| (port, o))
        .collect();
    for (gport, o) in &outbound_drain {
        io.pollfds.push(libc::pollfd { fd: o.fd, events: libc::POLLIN, revents: 0 });
        io.conn_ports.push(*gport);
    }
    let fixed_slots = io.pollfds.len();
    {
        let conns = shared.conns.lock().unwrap();
        for c in conns.values() {
            io.pollfds.push(libc::pollfd {
                fd: if c.host_fd >= 0 && c.state < ConnState::Closed { c.host_fd } else { -1 },
                events: libc::POLLIN, revents: 0,
            });
            io.conn_ports.push(c.src_port);
        }
    }

    let ready = unsafe {
        libc::poll(io.pollfds.as_mut_ptr(), io.pollfds.len() as u32, timeout_ms)
    };
    if ready <= 0 { return any_injected; }

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
            let n = unsafe {
                libc::read(io.wake_pipe_read, tmp.as_mut_ptr() as *mut _, tmp.len())
            };
            if n <= 0 { break; }
        }
        any_injected = true;
    }

    // ── Drain UDP relay siblings that fired ────────────────────────
    {
        let udp_drain: Vec<(i32, u16, IpFamily)> = io.udps.iter()
            .map(|u| (u.fd, u.guest_port, u.family))
            .collect();
        for (i, (fd, gp, family)) in udp_drain.into_iter().enumerate() {
            if io.pollfds[udp_slot_start + i].revents & libc::POLLIN != 0 {
                match family {
                    IpFamily::V4 => handle_udp_rx(io, &qsnap, fd, gp, single_queue),
                    IpFamily::V6 => handle_udp_rx_v6(io, &qsnap, fd, gp, single_queue),
                }
                any_injected = true;
            }
        }
    }

    // ── Inline accept on shared TCP listen fds ─────────────────────
    // Every vCPU polls the same listen fds; whichever one's `poll`
    // returned POLLIN tries to accept. `accept` is non-blocking and
    // thread-safe across the listen fd, so concurrent vCPUs racing
    // here all end up with exactly one winner per pending SYN — the
    // rest see `EAGAIN` and move on. We loop to drain the listen
    // backlog in one shot; `EAGAIN` breaks the inner loop.
    //
    // On a successful accept we:
    //   1. Flip client to non-blocking + TCP_NODELAY so the
    //      subsequent data plane sees low-latency small writes.
    //   2. Allocate a guest-visible pseudo-ephemeral source port.
    //   3. Build a synthetic SYN frame from the fake client and
    //      push it onto this vCPU's own `tx_replies`. The SYN
    //      gets drained and injected into the guest RX queue on
    //      the next iteration of this same `vcpu_poll` call —
    //      one `poll(2)` cycle of latency, replacing the previous
    //      mutex-locked hand-off + wake-pipe + `hv_vcpus_exit`
    //      doorbell chain from the dedicated accept thread.
    //   4. Insert the matching `ProxyConn` into this vCPU's own
    //      `WORKERS[id].conns` so the subsequent SYN+ACK / ACK /
    //      payload frames all thread through this vCPU's state.
    //      No cross-vCPU mutex contention — only one vCPU ever
    //      writes to a given `WORKERS[id]`.
    if !listens.is_empty() {
        let mut accepted_any = false;
        for (i, listen) in listens.iter().enumerate() {
            if io.pollfds[listen_slot_start + i].revents & libc::POLLIN == 0 {
                continue;
            }
            loop {
                let client_fd = unsafe {
                    libc::accept(listen.fd, std::ptr::null_mut(), std::ptr::null_mut())
                };
                if client_fd < 0 { break; }
                unsafe {
                    libc::fcntl(client_fd, libc::F_SETFL, libc::O_NONBLOCK);
                    let one: i32 = 1;
                    libc::setsockopt(
                        client_fd, libc::IPPROTO_TCP, libc::TCP_NODELAY,
                        &one as *const _ as *const _, 4,
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
                    IpFamily::V4 => alloc_src_port_for_vcpu(
                        io.id, cpu_count, listen.guest_port,
                    ),
                    IpFamily::V6 => alloc_src_port(),
                };
                let frame = build_tcp_reply(
                    listen.family, src_port, listen.guest_port,
                    1000, 0, 0x02, &[],
                );
                shared.tx_replies.lock().unwrap().push_back(frame);
                shared.conns.lock().unwrap().insert(src_port, ProxyConn {
                    host_fd: client_fd, src_port, guest_port: listen.guest_port,
                    my_seq: 1001, peer_ack: 0,
                    state: ConnState::SynSent, pending: Vec::new(),
                    family: listen.family,
                });
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
                if !qsnap.ready || !inject_frame(f.as_slice(), &qsnap, &mut io.rx_last) {
                    replies.push_front(f);
                    break;
                }
                any_injected = true;
            }
            drop(replies);
            if any_injected {
                unsafe { core::arch::asm!("dsb sy", options(nostack)); }
                if single_queue {
                    unsafe { hvf::hv_gic_set_spi(35, true); hvf::hv_gic_set_spi(35, false); }
                }
            }
        }
    }

    // ── Drain outbound-UDP NAT replies ─────────────────────────────
    // For each outbound flow whose fd fired POLLIN, recvfrom in a
    // loop until EAGAIN, build a UDP frame back to the guest using
    // the flow's saved `last_dst_*` (so the guest's stack accepts
    // the reply as coming from the original destination), and push
    // it to `tx_replies` for injection on the next iteration.
    if !outbound_drain.is_empty() {
        for (i, (gport, o)) in outbound_drain.iter().enumerate() {
            if io.pollfds[outbound_slot_start + i].revents
                & (libc::POLLIN | libc::POLLHUP)
                == 0
            {
                continue;
            }
            loop {
                let mut buf = [0u8; 1500];
                let n = unsafe {
                    libc::recv(
                        o.fd,
                        buf.as_mut_ptr() as *mut _,
                        buf.len(),
                        0,
                    )
                };
                if n <= 0 { break; }
                let payload = &buf[..n as usize];
                let frame = build_udp_frame_in(
                    &io.guest_mac,
                    o.last_dst_ip,
                    o.last_dst_port,
                    *gport,
                    payload,
                );
                shared.tx_replies.lock().unwrap().push_back(frame);
                any_injected = true;
            }
        }
    }

    // ── Zero-copy RX from established TCP conns ────────────────────
    // v4 header: virtio(12) + eth(14) + ip(20) + tcp(20) = 66.
    // v6 header: virtio(12) + eth(14) + ipv6(40) + tcp(20) = 86.
    // MTU 1500 caps the v4 MSS at 1460 and the v6 MSS at 1440;
    // we read at most that many bytes into the right offset of
    // the guest descriptor before stamping headers around it.
    const HDR_LEN_V4: usize = VIRTIO_NET_HDR_SIZE + 14 + 20 + 20;
    const HDR_LEN_V6: usize = VIRTIO_NET_HDR_SIZE + 14 + 40 + 20;
    const MAX_PAYLOAD_V4: usize = 1460;
    const MAX_PAYLOAD_V6: usize = 1440;
    struct ConnSnap { port: u16, guest_port: u16, fd: i32, seq: u32, ack: u32, family: IpFamily }

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
                                port, guest_port: c.guest_port, fd: c.host_fd,
                                seq: c.my_seq, ack: c.peer_ack, family: c.family,
                            })
                        } else { None }
                    })
                })
                .collect()
        };

        struct RxResult { port: u16, seq_advance: u32, eof: bool }
        let mut results: Vec<RxResult> = Vec::new();
        let mut injected = false;

        for cs in &snaps {
            if !qsnap.ready { continue; }

            let avail_idx = unsafe {
                core::ptr::read_volatile(qsnap.gpa_to_host(qsnap.avail_addr + 2) as *const u16)
            };
            if io.rx_last == avail_idx { continue; }
            let ring_idx = io.rx_last & (qsnap.qsize - 1);
            let desc_idx = unsafe {
                core::ptr::read_volatile(
                    qsnap.gpa_to_host(qsnap.avail_addr + 4 + ring_idx as u64 * 2) as *const u16)
            };
            let buf_addr = unsafe {
                core::ptr::read_unaligned(
                    qsnap.gpa_to_host(qsnap.desc_addr + desc_idx as u64 * 16) as *const u64)
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
                    results.push(RxResult { port: cs.port, seq_advance: 0, eof: true });
                }
                continue;
            }
            let payload_len = n as usize;

            let addrs = match cs.family {
                IpFamily::V4 => IpAddrPair::V4 { src: GW_IP, dst: VM_IP },
                IpFamily::V6 => IpAddrPair::V6 { src: GW_IPV6, dst: VM_IPV6 },
            };
            let total = write_tcp_frame_around_payload(
                guest_buf, &GUEST_MAC, &addrs,
                cs.port, cs.guest_port, cs.seq, cs.ack, 0x18, payload_len);

            let used_idx = io.rx_last;
            unsafe {
                let entry = qsnap.gpa_to_host(qsnap.used_addr + 4 + (used_idx & (qsnap.qsize - 1)) as u64 * 8);
                core::ptr::write_unaligned(entry as *mut u32, desc_idx as u32);
                core::ptr::write_unaligned(entry.add(4) as *mut u32, total as u32);
                core::ptr::write_volatile(qsnap.gpa_to_host(qsnap.used_addr + 2) as *mut u16,
                    used_idx.wrapping_add(1));
            }
            io.rx_last = io.rx_last.wrapping_add(1);
            results.push(RxResult { port: cs.port, seq_advance: payload_len as u32, eof: false });
            injected = true;
        }

        if !results.is_empty() {
            let mut conns = shared.conns.lock().unwrap();
            for r in &results {
                if let Some(c) = conns.get_mut(&r.port) {
                    if r.eof {
                        let frame = build_tcp_reply(c.family,
                            c.src_port, c.guest_port, c.my_seq, c.peer_ack, 0x11, &[]);
                        c.my_seq = c.my_seq.wrapping_add(1);
                        c.state = ConnState::Closed;
                        // Mirror the guest-initiated FIN path in handle_tcp:
                        // drop the host fd now so the kernel socket leaves
                        // CLOSE_WAIT instead of leaking until process exit.
                        unsafe { libc::close(c.host_fd); }
                        c.host_fd = -1;
                        inject_frame(frame.as_slice(), &qsnap, &mut io.rx_last);
                        injected = true;
                    } else {
                        c.my_seq = c.my_seq.wrapping_add(r.seq_advance);
                    }
                }
            }
        }

        if injected {
            unsafe { core::arch::asm!("dsb sy", options(nostack)); }
            if single_queue {
                unsafe { hvf::hv_gic_set_spi(35, true); hvf::hv_gic_set_spi(35, false); }
            }
            any_injected = true;
        }
    } else {
        // RX queue not ready — buffer data in pending.
        let mut conns = shared.conns.lock().unwrap();
        for i in fixed_slots..io.pollfds.len() {
            if io.pollfds[i].revents & (libc::POLLIN | libc::POLLHUP) == 0 { continue; }
            let port = io.conn_ports[i];
            if let Some(c) = conns.get_mut(&port) {
                if c.host_fd < 0 { continue; }
                let n = unsafe {
                    libc::read(c.host_fd, io.read_buf.as_mut_ptr() as *mut _, io.read_buf.len())
                };
                if n > 0 { c.pending.extend_from_slice(&io.read_buf[..n as usize]); }
            }
        }
    }

    // Periodic closed-conn cleanup.
    io.cleanup_ctr = io.cleanup_ctr.wrapping_add(1);
    if io.cleanup_ctr % 1000 == 0 {
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
            p + 1, 40000, Ordering::Relaxed, Ordering::Relaxed);
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
fn alloc_src_port_for_vcpu(
    target_vcpu: usize,
    cpu_count: usize,
    dst_port: u16,
) -> u16 {
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

/// Drain a UDP relay sibling fd owned by this worker, injecting frames
/// into the worker's own RX queue. Because each worker owns its own
/// sibling fd (distributed by SO_REUSEPORT hashing at bind time), there's
/// no cross-worker software RSS needed — the kernel already routed the
/// datagram to us.
fn handle_udp_rx(io: &mut IoState, qsnap: &virtio::QueueSnapshot,
                 fd: i32, guest_port: u16, single_queue: bool) {
    let shared = worker_shared(io.id);
    let mut any_injected = false;
    let mut ring_full = false;

    loop {
        let mut client_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut addr_len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in>() as u32;
        let n = unsafe {
            libc::recvfrom(fd, io.read_buf.as_mut_ptr() as *mut _,
                io.read_buf.len(), 0,
                &mut client_addr as *mut _ as *mut libc::sockaddr,
                &mut addr_len)
        };
        if n <= 0 { break; }
        let payload_len = n as usize;

        let client_port = u16::from_be(client_addr.sin_port);

        // Register the sender → sockaddr mapping BEFORE publishing the
        // packet into the guest ring, so the vCPU's handle_udp sees it
        // when the echo reply comes back.
        {
            let mut m = shared.udp_clients.lock().unwrap();
            m.insert((guest_port, client_port), client_addr);
        }

        if !qsnap.ready {
            ring_full = true;
            continue;
        }

        let frame_len = build_udp_frame(&mut io.frame_buf, &io.guest_mac,
            GW_IP, VM_IP, client_port, guest_port,
            &io.read_buf[..payload_len]);
        if !inject_frame(&io.frame_buf[..frame_len], qsnap, &mut io.rx_last) {
            ring_full = true;
            continue;
        }
        any_injected = true;
    }

    if !any_injected && !ring_full {
        return;
    }
    unsafe { core::arch::asm!("dsb sy", options(nostack)); }
    if single_queue {
        unsafe {
            hvf::hv_gic_set_spi(35, true);
            hvf::hv_gic_set_spi(35, false);
        }
    }
    // Multi-queue: no kick — we're already on the vCPU thread, the
    // guest will see the new RX frames as soon as we return to it.
    let _ = io.id;
}

fn inject_frame(frame: &[u8], snap: &virtio::QueueSnapshot, rx_last: &mut u16) -> bool {
    let avail_idx = unsafe {
        core::ptr::read_volatile(snap.gpa_to_host(snap.avail_addr + 2) as *const u16)
    };
    let last = *rx_last;
    if last == avail_idx { return false; }
    let ring_idx = last & (snap.qsize - 1);
    let desc_idx = unsafe {
        core::ptr::read_volatile(
            snap.gpa_to_host(snap.avail_addr + 4 + ring_idx as u64 * 2) as *const u16)
    };
    let addr = unsafe {
        core::ptr::read_unaligned(
            snap.gpa_to_host(snap.desc_addr + desc_idx as u64 * 16) as *const u64)
    };
    unsafe {
        core::ptr::copy_nonoverlapping(frame.as_ptr(), snap.gpa_to_host(addr), frame.len());
    }
    let used_idx = unsafe {
        core::ptr::read_volatile(snap.gpa_to_host(snap.used_addr + 2) as *const u16)
    };
    unsafe {
        let entry = snap.gpa_to_host(snap.used_addr + 4 + (used_idx & (snap.qsize - 1)) as u64 * 8);
        core::ptr::write_unaligned(entry as *mut u32, desc_idx as u32);
        core::ptr::write_unaligned(entry.add(4) as *mut u32, frame.len() as u32);
        core::ptr::write_volatile(snap.gpa_to_host(snap.used_addr + 2) as *mut u16,
            used_idx.wrapping_add(1));
        // Flush the cache line containing used->idx so the guest PE sees it.
        // Apple Silicon HVF should be cache-coherent, but empirically the
        // guest reads stale used->idx on secondary queues without this.
        let used_ptr = snap.gpa_to_host(snap.used_addr + 2);
        core::arch::asm!(
            "dc cvau, {addr}",
            "dsb sy",
            addr = in(reg) used_ptr,
            options(nostack),
        );
    }
    *rx_last = last.wrapping_add(1);
    true
}

fn inject_data_frames(c: &mut ProxyConn, data: &[u8], mac: &[u8; 6],
                      snap: &virtio::QueueSnapshot, rx_last: &mut u16,
                      frame_buf: &mut [u8; 2048]) {
    let max_chunk = match c.family {
        IpFamily::V4 => 1460,
        IpFamily::V6 => 1440,
    };
    let addrs = match c.family {
        IpFamily::V4 => IpAddrPair::V4 { src: GW_IP, dst: VM_IP },
        IpFamily::V6 => IpAddrPair::V6 { src: GW_IPV6, dst: VM_IPV6 },
    };
    let mut off = 0;
    while off < data.len() {
        let chunk = (data.len() - off).min(max_chunk);
        let len = write_tcp_frame(frame_buf, mac, &addrs,
            c.src_port, c.guest_port, c.my_seq, c.peer_ack, 0x18,
            &data[off..off + chunk]);
        c.my_seq = c.my_seq.wrapping_add(chunk as u32);
        off += chunk;
        inject_frame(&frame_buf[..len], snap, rx_last);
    }
}


// ── Guest TX (vCPU thread) ──────────────────────────────────────────────────

fn handle_guest_tx(frame: &[u8]) {
    if frame.len() < 14 { return; }
    let guest_mac: [u8; 6] = frame[6..12].try_into().unwrap_or([0; 6]);
    match u16::from_be_bytes([frame[12], frame[13]]) {
        0x0806 => handle_arp(&frame[14..]),
        0x0800 => handle_ipv4(&frame[14..]),
        0x86dd => handle_ipv6(&frame[14..], guest_mac),
        _ => {}
    }
}

// ── IPv6: NDP responder + ICMPv6 echo bounce + L4 relay ────────
//
// Mirrors the v4 path: NS → NA, ICMPv6 Echo Request → Reply, and
// host-side AF_INET6 sockets bridged to the guest for both UDP
// (`handle_udp_v6`) and TCP (`handle_tcp` with `IpFamily::V6`).
// `bind_listen_v6` and `open_udp_sibling_v6` set up the listeners
// in `start()`; reply frames go through the v6 frame builders
// keyed off the conn's / relay's `family` tag.

fn handle_ipv6(ip: &[u8], guest_mac: [u8; 6]) {
    if ip.len() < 40 { return; }
    let payload_len = u16::from_be_bytes([ip[4], ip[5]]) as usize;
    let next_header = ip[6];
    if 40 + payload_len > ip.len() { return; }
    let src_ip: [u8; 16] = ip[8..24].try_into().unwrap_or([0; 16]);
    let dst_ip: [u8; 16] = ip[24..40].try_into().unwrap_or([0; 16]);
    let payload = &ip[40..40 + payload_len];

    match next_header {
        58 => {
            if payload.is_empty() { return; }
            match payload[0] {
                128 => bounce_icmpv6_echo(src_ip, dst_ip, payload, guest_mac),
                135 => reply_neighbor_solicitation(src_ip, payload, guest_mac),
                _ => {}
            }
        }
        17 => handle_udp_v6(payload, src_ip, dst_ip),
        6 => handle_tcp(IpFamily::V6, payload),
        _ => {}
    }
}

// ── IPv6 UDP relay ─────────────────────────────────────────────
//
// Mirrors the v4 UDP path (`handle_udp_rx` worker-side, `handle_udp`
// vCPU-side) for inbound + reply traffic over IPv6. The runner
// holds an AF_INET6 socket bound to `::1:host_port` per
// `-p udp:H:G` mapping; datagrams arriving there get translated
// into IPv6 UDP frames addressed to the VM's link-local; the VM's
// reply hits `handle_udp_v6`, which `sendto`s back to the
// remembered `sockaddr_in6`.

/// Build a UDP-over-IPv6 frame: virtio_net_hdr | Eth | IPv6 | UDP
/// | payload. Returns total bytes written into `buf`.
fn build_udp_frame_v6(
    buf: &mut [u8],
    dst_mac: &[u8; 6],
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> usize {
    let udp_len = 8 + payload.len();
    let total = VIRTIO_NET_HDR_SIZE + 14 + 40 + udp_len;
    debug_assert!(total <= buf.len());
    buf[..VIRTIO_NET_HDR_SIZE].fill(0);
    let mut o = VIRTIO_NET_HDR_SIZE;
    buf[o..o+6].copy_from_slice(dst_mac); o += 6;
    buf[o..o+6].copy_from_slice(&GW_MAC); o += 6;
    buf[o..o+2].copy_from_slice(&0x86ddu16.to_be_bytes()); o += 2;
    // IPv6 header.
    buf[o..o+4].copy_from_slice(&0x6000_0000u32.to_be_bytes()); o += 4;
    buf[o..o+2].copy_from_slice(&(udp_len as u16).to_be_bytes()); o += 2;
    buf[o] = 17; o += 1; // next_header = UDP
    buf[o] = 64; o += 1; // hop limit
    buf[o..o+16].copy_from_slice(src_ip); o += 16;
    buf[o..o+16].copy_from_slice(dst_ip); o += 16;
    // UDP header + payload first (with checksum=0), then patch in
    // the pseudo-header checksum over header+payload.
    let us = o;
    buf[o..o+2].copy_from_slice(&src_port.to_be_bytes()); o += 2;
    buf[o..o+2].copy_from_slice(&dst_port.to_be_bytes()); o += 2;
    buf[o..o+2].copy_from_slice(&(udp_len as u16).to_be_bytes()); o += 2;
    buf[o..o+2].fill(0); o += 2; // checksum placeholder
    buf[o..o+payload.len()].copy_from_slice(payload);
    let cksum = ipv6_pseudo_checksum(src_ip, dst_ip, 17, &buf[us..us+udp_len]);
    buf[us+6..us+8].copy_from_slice(&cksum.to_be_bytes());
    total
}

/// VM IPv6 link-local — derived from `GUEST_MAC` via modified
/// EUI-64 (mirrors what the unikernel computes at boot).
const VM_IPV6: [u8; 16] = [
    0xfe, 0x80, 0, 0, 0, 0, 0, 0,
    GUEST_MAC[0] ^ 0x02, GUEST_MAC[1], GUEST_MAC[2],
    0xff, 0xfe,
    GUEST_MAC[3], GUEST_MAC[4], GUEST_MAC[5],
];

/// Worker-side IPv6 UDP RX. Reads from the AF_INET6 sibling fd,
/// records the `(guest_port, client_port) → sockaddr_in6` mapping
/// in `udp_clients_v6`, and injects a UDP-over-IPv6 frame into
/// the guest. Mirrors `handle_udp_rx` for v4.
fn handle_udp_rx_v6(
    io: &mut IoState,
    qsnap: &virtio::QueueSnapshot,
    fd: i32,
    guest_port: u16,
    single_queue: bool,
) {
    let shared = worker_shared(io.id);
    let mut any_injected = false;
    let mut ring_full = false;
    loop {
        let mut client_addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut addr_len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in6>() as u32;
        let n = unsafe {
            libc::recvfrom(fd, io.read_buf.as_mut_ptr() as *mut _,
                io.read_buf.len(), 0,
                &mut client_addr as *mut _ as *mut libc::sockaddr,
                &mut addr_len)
        };
        if n <= 0 { break; }
        let payload_len = n as usize;
        let client_port = u16::from_be(client_addr.sin6_port);

        {
            let mut m = shared.udp_clients_v6.lock().unwrap();
            m.insert((guest_port, client_port), client_addr);
        }

        if !qsnap.ready { ring_full = true; continue; }

        // Source address from the host's perspective: GW_IPV6
        // (the runner's gateway). Destination = VM_IPV6.
        let frame_len = build_udp_frame_v6(
            &mut io.frame_buf,
            &io.guest_mac,
            &GW_IPV6, &VM_IPV6,
            client_port, guest_port,
            &io.read_buf[..payload_len],
        );
        if !inject_frame(&io.frame_buf[..frame_len], qsnap, &mut io.rx_last) {
            ring_full = true; continue;
        }
        any_injected = true;
    }
    if !any_injected && !ring_full { return; }
    unsafe { core::arch::asm!("dsb sy", options(nostack)); }
    if single_queue {
        unsafe {
            hvf::hv_gic_set_spi(35, true);
            hvf::hv_gic_set_spi(35, false);
        }
    }
    let _ = io.id;
}

/// vCPU-side handler for guest-TX UDP-over-IPv6 packets.
/// Distinguishes:
///   * Reply path: `src_port` matches a `UDP_RELAYS_V6` entry's
///     `guest_port` → look up the original `sockaddr_in6` in
///     `udp_clients_v6` and `sendto` back to the host.
///   * Outbound (guest-initiated): not supported yet — DHCP
///     equivalent for v6 is SLAAC, which doesn't go through the
///     runner; other outbound v6 patterns aren't a real use case
///     for us right now.
fn handle_udp_v6(udp: &[u8], _src_ip: [u8; 16], _dst_ip: [u8; 16]) {
    if udp.len() < 8 { return; }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let payload = &udp[8..];
    if payload.is_empty() { return; }

    let vcpu_id = CURRENT_VCPU.with(|c| c.get());
    let inbound = UDP_RELAYS_V6.get().and_then(|table| {
        table.iter().find(|r| r.guest_port == src_port)
    });
    let relay = match inbound {
        Some(r) => r,
        None => return,
    };
    let fd = match relay.fds.get(vcpu_id).or_else(|| relay.fds.first()) {
        Some(&fd) => fd,
        None => return,
    };
    let client_addr = {
        let guard = my_worker_shared().udp_clients_v6.lock().unwrap();
        guard.get(&(src_port, dst_port)).copied()
    };
    if let Some(addr) = client_addr {
        unsafe {
            libc::sendto(fd, payload.as_ptr() as *const _, payload.len(),
                0, &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as u32);
        }
    }
}

/// IPv6 pseudo-header checksum (RFC 8200 §8.1) over the upper-
/// layer payload (already includes any embedded checksum field
/// set to zero).
fn ipv6_pseudo_checksum(src: &[u8; 16], dst: &[u8; 16], next_hdr: u8, payload: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in src.chunks(2).chain(dst.chunks(2)) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    let len = payload.len() as u32;
    sum += (len >> 16) & 0xffff;
    sum += len & 0xffff;
    sum += next_hdr as u32;
    let mut i = 0;
    while i + 2 <= payload.len() {
        sum += u16::from_be_bytes([payload[i], payload[i + 1]]) as u32;
        i += 2;
    }
    if i < payload.len() {
        sum += (payload[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an IPv6 packet header into `out` and return the total
/// frame length written (header + payload). Caller has already
/// reserved space for the Ethernet header at `out[..14]`.
fn build_ipv6_frame(
    dst_mac: &[u8; 6],
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    next_header: u8,
    hop_limit: u8,
    payload: &[u8],
    out: &mut [u8],
) -> usize {
    let total = VIRTIO_NET_HDR_SIZE + 14 + 40 + payload.len();
    if out.len() < total { return 0; }
    let mut o = VIRTIO_NET_HDR_SIZE;
    out[o..o+6].copy_from_slice(dst_mac); o += 6;
    out[o..o+6].copy_from_slice(&GW_MAC); o += 6;
    out[o..o+2].copy_from_slice(&0x86ddu16.to_be_bytes()); o += 2;
    // IPv6 fixed header.
    out[o..o+4].copy_from_slice(&0x6000_0000u32.to_be_bytes()); o += 4;
    out[o..o+2].copy_from_slice(&(payload.len() as u16).to_be_bytes()); o += 2;
    out[o] = next_header; o += 1;
    out[o] = hop_limit; o += 1;
    out[o..o+16].copy_from_slice(src_ip); o += 16;
    out[o..o+16].copy_from_slice(dst_ip); o += 16;
    out[o..o+payload.len()].copy_from_slice(payload);
    total
}

/// Reply to an inbound Neighbor Solicitation for our gateway
/// address. The VM's IPv6 stack drives this on bring-up to learn
/// the gateway MAC (mirrors how it ARP-resolves `GW_IP` for v4).
fn reply_neighbor_solicitation(src_ip: [u8; 16], ns: &[u8], guest_mac: [u8; 6]) {
    if ns.len() < 24 { return; }
    let target: [u8; 16] = ns[8..24].try_into().unwrap_or([0; 16]);
    if target != GW_IPV6 { return; }
    // Build NA: type=136, code=0, cksum=0, flags(S|O), reserved[3], target[16],
    //           TLLA option (type=2, len=1, GW_MAC[6]).
    let mut na = [0u8; 32];
    na[0] = 136; na[1] = 0;
    na[4] = 0x60; // S=1, O=1 (no Router flag)
    na[8..24].copy_from_slice(&GW_IPV6);
    na[24] = 2; na[25] = 1;
    na[26..32].copy_from_slice(&GW_MAC);
    let cksum = ipv6_pseudo_checksum(&GW_IPV6, &src_ip, 58, &na);
    na[2..4].copy_from_slice(&cksum.to_be_bytes());

    let mut frame = [0u8; MAX_REPLY_FRAME];
    let n = build_ipv6_frame(&guest_mac, &GW_IPV6, &src_ip, 58, 255, &na, &mut frame);
    if n == 0 { return; }
    let mut f = TxFrame { data: [0u8; MAX_REPLY_FRAME], len: 0 };
    f.data[..n].copy_from_slice(&frame[..n]);
    f.len = n as u16;
    my_worker_shared().tx_replies.lock().unwrap().push_back(f);
}

/// Bounce ICMPv6 Echo Request → Echo Reply. Mirrors the standard
/// host-to-host ping6 behaviour but sourced from the runner's
/// gateway, so `ping6 fe80::aabb:ccff:fedd:eeff` from inside the
/// VM gets replies even when no real host is reachable.
fn bounce_icmpv6_echo(src_ip: [u8; 16], dst_ip: [u8; 16], echo_req: &[u8], guest_mac: [u8; 6]) {
    if echo_req.len() < 8 { return; }
    let mut reply = vec![0u8; echo_req.len()];
    reply.copy_from_slice(echo_req);
    reply[0] = 129; // Echo Reply
    reply[1] = 0;
    reply[2] = 0; reply[3] = 0; // checksum placeholder
    let _ = dst_ip; // dst was us (or a multicast we joined); reply src = us.
    let cksum = ipv6_pseudo_checksum(&GW_IPV6, &src_ip, 58, &reply);
    reply[2..4].copy_from_slice(&cksum.to_be_bytes());

    let mut frame = [0u8; MAX_REPLY_FRAME];
    let n = build_ipv6_frame(&guest_mac, &GW_IPV6, &src_ip, 58, 64, &reply, &mut frame);
    if n == 0 { return; }
    let mut f = TxFrame { data: [0u8; MAX_REPLY_FRAME], len: 0 };
    f.data[..n].copy_from_slice(&frame[..n]);
    f.len = n as u16;
    my_worker_shared().tx_replies.lock().unwrap().push_back(f);
}

fn handle_arp(arp: &[u8]) {
    if arp.len() < 28 { return; }
    if u16::from_be_bytes([arp[6], arp[7]]) != 1 { return; }
    if arp[24..28] != GW_IP { return; }
    let guest_mac: [u8; 6] = arp[8..14].try_into().unwrap_or([0; 6]);
    let mut f = TxFrame { data: [0u8; MAX_REPLY_FRAME], len: 0, };
    {
        let b = &mut f.data;
        let mut o = VIRTIO_NET_HDR_SIZE; // virtio-net hdr (zeroed)
        b[o..o+6].copy_from_slice(&guest_mac); o += 6;
        b[o..o+6].copy_from_slice(&GW_MAC); o += 6;
        b[o..o+2].copy_from_slice(&0x0806u16.to_be_bytes()); o += 2;
        b[o..o+2].copy_from_slice(&1u16.to_be_bytes()); o += 2;
        b[o..o+2].copy_from_slice(&0x0800u16.to_be_bytes()); o += 2;
        b[o] = 6; b[o+1] = 4; o += 2;
        b[o..o+2].copy_from_slice(&2u16.to_be_bytes()); o += 2;
        b[o..o+6].copy_from_slice(&GW_MAC); o += 6;
        b[o..o+4].copy_from_slice(&GW_IP); o += 4;
        b[o..o+6].copy_from_slice(&arp[8..14]); o += 6;
        b[o..o+4].copy_from_slice(&arp[14..18]); o += 4;
        f.len = o as u16;
    }
    my_worker_shared().tx_replies.lock().unwrap().push_back(f);
}

fn handle_ipv4(ip: &[u8]) {
    if ip.len() < 20 { return; }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    let src_ip: [u8; 4] = ip[12..16].try_into().unwrap_or([0; 4]);
    let dst_ip: [u8; 4] = ip[16..20].try_into().unwrap_or([0; 4]);
    match ip[9] {
        6 => handle_tcp(IpFamily::V4, &ip[ihl..]),
        17 => handle_udp(&ip[ihl..], src_ip, dst_ip),
        _ => {}
    }
}

fn handle_tcp(family: IpFamily, tcp: &[u8]) {
    if tcp.len() < 20 { return; }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    let flags = tcp[13];
    let payload = if tcp.len() > data_offset { &tcp[data_offset..] } else { &[] };

    // The vCPU only processes conns that its paired worker accepted, so
    // the lookup is scoped to this worker's local `conns` map.
    let shared = my_worker_shared();

    // Snapshot connection state under brief lock — don't hold across write().
    struct TxSnap { fd: i32, port: u16, guest_port: u16, seq: u32, ack: u32, state: ConnState }
    let snap = {
        let mut conns = shared.conns.lock().unwrap();
        if flags & 0x04 != 0 {
            if let Some(c) = conns.get_mut(&dst_port) {
                if c.host_fd >= 0 {
                    // RST the host-side socket too — set SO_LINGER
                    // {1,0} so close() emits RST instead of the
                    // default FIN-ACK dance, mirroring what the guest
                    // just sent. Without this the host TCP socket
                    // sits in ESTABLISHED until keepalive (minutes).
                    let linger = libc::linger { l_onoff: 1, l_linger: 0 };
                    unsafe {
                        libc::setsockopt(
                            c.host_fd, libc::SOL_SOCKET, libc::SO_LINGER,
                            &linger as *const _ as *const _,
                            std::mem::size_of::<libc::linger>() as u32,
                        );
                        libc::close(c.host_fd);
                    }
                    c.host_fd = -1;
                }
                c.state = ConnState::Closed;
            }
            return;
        }
        let c = match conns.get_mut(&dst_port) {
            Some(c) => c, None => return,
        };
        let s = TxSnap {
            fd: c.host_fd, port: c.src_port, guest_port: c.guest_port,
            seq: c.my_seq, ack: c.peer_ack, state: c.state,
        };
        // Update state eagerly (before dropping lock).
        match c.state {
            ConnState::SynSent => {
                if flags & 0x12 == 0x12 {
                    c.peer_ack = seq.wrapping_add(1);
                    c.state = ConnState::Established;
                }
            }
            ConnState::Established => {
                if !payload.is_empty() {
                    c.peer_ack = seq.wrapping_add(payload.len() as u32);
                }
                if flags & 0x01 != 0 {
                    c.peer_ack = c.peer_ack.wrapping_add(1);
                    c.my_seq = c.my_seq.wrapping_add(1);
                    c.state = ConnState::Closed;
                    unsafe { libc::close(c.host_fd); }
                    c.host_fd = -1;
                }
            }
            _ => {}
        }
        s
    }; // conns lock released

    // write() outside both conns and tx_replies locks — no contention.
    if snap.state == ConnState::Established && !payload.is_empty() {
        let mut written = 0usize;
        while written < payload.len() {
            let n = unsafe {
                libc::write(snap.fd,
                    payload.as_ptr().add(written) as *const _,
                    payload.len() - written)
            };
            if n <= 0 { break; }
            written += n as usize;
        }
    }

    // Brief lock: push reply frames into this worker's tx_replies slice.
    let mut replies = shared.tx_replies.lock().unwrap();
    match snap.state {
        ConnState::SynSent => {
            if flags & 0x12 == 0x12 {
                let ack = seq.wrapping_add(1);
                let f = build_tcp_reply(family,
                    snap.port, snap.guest_port, snap.seq, ack, 0x10, &[]);
                replies.push_back(f);
            }
        }
        ConnState::Established => {
            if !payload.is_empty() {
                let ack = seq.wrapping_add(payload.len() as u32);
                let f = build_tcp_reply(family,
                    snap.port, src_port, snap.seq, ack, 0x10, &[]);
                replies.push_back(f);
            }
            if flags & 0x01 != 0 {
                let ack = snap.ack.wrapping_add(1);
                let f = build_tcp_reply(family,
                    snap.port, src_port, snap.seq, ack, 0x11, &[]);
                replies.push_back(f);
            }
        }
        _ => {}
    }
}

fn handle_udp(udp: &[u8], _src_ip: [u8; 4], dst_ip: [u8; 4]) {
    if udp.len() < 8 { return; }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    // DHCP: guest port 68 → server port 67.
    if src_port == 68 && dst_port == 67 {
        handle_dhcp(&udp[8..]);
        return;
    }
    let payload = &udp[8..];
    if payload.is_empty() { return; }

    // First try the inbound-relay reply path: the guest is replying
    // to a client whose datagram came in via one of our `-p udp:H:G`
    // mappings. Match by `src_port == guest_port` of a relay entry.
    let vcpu_id = CURRENT_VCPU.with(|c| c.get());
    let inbound = UDP_RELAYS.get().and_then(|table| {
        table.iter().find(|r| r.guest_port == src_port)
    });
    if let Some(relay) = inbound {
        // Per-vCPU sibling fd; fall back to sibling 0 if the
        // vCPU id is out of range (shouldn't happen).
        let fd = match relay.fds.get(vcpu_id).or_else(|| relay.fds.first()) {
            Some(&fd) => fd,
            None => return,
        };
        let client_addr = {
            let guard = my_worker_shared().udp_clients.lock().unwrap();
            guard.get(&(src_port, dst_port)).copied()
        };
        if let Some(addr) = client_addr {
            unsafe {
                libc::sendto(fd, payload.as_ptr() as *const _, payload.len(),
                    0, &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32);
            }
        }
        return;
    }

    // Outbound: guest is initiating a UDP flow (gateway / sidecar
    // pattern). Forward to (host_loopback, dst_port) — the only
    // host-side reachable destination in HVF user-mode networking
    // is loopback; we map any guest-side dst_ip (typically the
    // virtual gateway 10.0.2.2) to 127.0.0.1. Open a fresh
    // unbound UDP socket per guest src_port, register it with this
    // vCPU's poll loop, and remember the original dst for the
    // synthesised reply frame.
    handle_udp_outbound(src_port, dst_ip, dst_port, payload);
}

/// Allocate (or reuse) an outbound NAT fd for the given guest
/// `src_port` on the current vCPU and forward `payload` to
/// `(127.0.0.1, dst_port)`. Records the original guest-side dst
/// (`dst_ip`, `dst_port`) so when the host's reply lands on the fd
/// we can rebuild a UDP frame that the guest will accept (`src_ip`
/// = original dst, `src_port` = original dst_port, `dst` = guest).
fn handle_udp_outbound(
    guest_src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    payload: &[u8],
) {
    let vcpu_id = CURRENT_VCPU.with(|c| c.get());
    let vcpu_ios = match VCPU_IOS.get() {
        Some(v) => v,
        None => return,
    };
    let mut io = match vcpu_ios.get(vcpu_id) {
        Some(m) => m.lock().unwrap(),
        None => return,
    };
    let fd = match io.outbound_udp.get_mut(&guest_src_port) {
        Some(o) => {
            o.last_dst_ip = dst_ip;
            o.last_dst_port = dst_port;
            o.fd
        }
        None => unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if fd < 0 { return; }
            let flags = libc::fcntl(fd, libc::F_GETFL, 0);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            io.outbound_udp.insert(guest_src_port, OutboundUdp {
                fd,
                last_dst_ip: dst_ip,
                last_dst_port: dst_port,
            });
            fd
        },
    };
    // Forward to host loopback. The guest believes it's talking to
    // `dst_ip` (typically the gateway 10.0.2.2) but the only
    // host-reachable endpoint under user-mode networking is
    // 127.0.0.1; the synthesised reply will carry the original
    // `dst_ip` so the guest's stack accepts it.
    let host_addr = libc::sockaddr_in {
        #[cfg(target_os = "macos")]
        sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
        #[cfg(target_os = "macos")]
        sin_family: libc::AF_INET as u8,
        #[cfg(target_os = "linux")]
        sin_family: libc::AF_INET as u16,
        sin_port: dst_port.to_be(),
        sin_addr: libc::in_addr {
            // 127.0.0.1 in network-byte-order memory; see the
            // matching `from_ne_bytes` rationale in
            // uni-backend/native::udp_send.
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        },
        sin_zero: [0; 8],
    };
    unsafe {
        libc::sendto(
            fd,
            payload.as_ptr() as *const _,
            payload.len(),
            0,
            &host_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
    }
}

fn handle_dhcp(bootp: &[u8]) {
    if bootp.len() < 240 { return; }
    let mut msg_type: u8 = 0;
    let mut i = 240;
    while i < bootp.len() {
        let opt = bootp[i];
        if opt == 255 { break; } if opt == 0 { i += 1; continue; }
        if i + 1 >= bootp.len() { break; }
        let len = bootp[i + 1] as usize;
        if i + 2 + len > bootp.len() { break; }
        if opt == 53 && len >= 1 { msg_type = bootp[i + 2]; }
        i += 2 + len;
    }
    if msg_type != 1 && msg_type != 3 { return; }
    let reply_type: u8 = if msg_type == 1 { 2 } else { 5 };
    let guest_mac: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    // Build DHCP reply directly in a TxFrame (cold path, boot only).
    let mut f = TxFrame { data: [0u8; MAX_REPLY_FRAME], len: 0, };
    let b = &mut f.data;
    let mut o = VIRTIO_NET_HDR_SIZE; // skip virtio-net hdr (zeroed)
    b[o..o+6].fill(0xff); o += 6; b[o..o+6].copy_from_slice(&GW_MAC); o += 6;
    b[o..o+2].copy_from_slice(&0x0800u16.to_be_bytes()); o += 2;
    let ip_start = o; o += 20; // IP header (filled below)
    let udp_start = o; o += 8; // UDP header (filled below)
    let bp = o; o += 236; // BOOTP reply
    b[bp] = 2; b[bp+1] = 1; b[bp+2] = 6;
    b[bp+4..bp+8].copy_from_slice(&bootp[4..8]);
    b[bp+16..bp+20].copy_from_slice(&VM_IP); b[bp+20..bp+24].copy_from_slice(&GW_IP);
    b[bp+28..bp+34].copy_from_slice(&guest_mac);
    // DHCP options
    let opts: &[u8] = &[
        99,130,83,99, 53,1,reply_type,
        54,4,GW_IP[0],GW_IP[1],GW_IP[2],GW_IP[3],
        51,4,0,1,0x51,0x80, 1,4,255,255,255,0,
        3,4,GW_IP[0],GW_IP[1],GW_IP[2],GW_IP[3],
        6,4,10,0,2,3, 255,
    ];
    b[o..o+opts.len()].copy_from_slice(opts); o += opts.len();
    // Fill UDP header
    let ul = (o - udp_start) as u16;
    b[udp_start..udp_start+2].copy_from_slice(&67u16.to_be_bytes());
    b[udp_start+2..udp_start+4].copy_from_slice(&68u16.to_be_bytes());
    b[udp_start+4..udp_start+6].copy_from_slice(&ul.to_be_bytes());
    // Fill IP header
    let it = (o - ip_start) as u16;
    b[ip_start] = 0x45; b[ip_start+2..ip_start+4].copy_from_slice(&it.to_be_bytes());
    b[ip_start+6] = 0x40; b[ip_start+8] = 64; b[ip_start+9] = 17;
    b[ip_start+12..ip_start+16].copy_from_slice(&GW_IP);
    b[ip_start+16..ip_start+20].copy_from_slice(&BROADCAST_IP);
    let cs = ipv4_checksum(&b[ip_start..ip_start+20]);
    b[ip_start+10..ip_start+12].copy_from_slice(&cs.to_be_bytes());
    f.len = o as u16;
    my_worker_shared().tx_replies.lock().unwrap().push_back(f);
}

// ── Packet construction ─────────────────────────────────────────────────────

fn build_grat_arp_frame(mac: &[u8; 6]) -> TxFrame {
    let mut f = TxFrame { data: [0u8; MAX_REPLY_FRAME], len: 0, };
    let b = &mut f.data;
    let mut o = VIRTIO_NET_HDR_SIZE; // virtio-net hdr (zeroed)
    b[o..o+6].fill(0xff); o += 6;
    b[o..o+6].copy_from_slice(&GW_MAC); o += 6;
    b[o..o+2].copy_from_slice(&0x0806u16.to_be_bytes()); o += 2;
    b[o..o+2].copy_from_slice(&1u16.to_be_bytes()); o += 2;
    b[o..o+2].copy_from_slice(&0x0800u16.to_be_bytes()); o += 2;
    b[o] = 6; b[o+1] = 4; o += 2;
    b[o..o+2].copy_from_slice(&2u16.to_be_bytes()); o += 2;
    b[o..o+6].copy_from_slice(&GW_MAC); o += 6;
    b[o..o+4].copy_from_slice(&GW_IP); o += 4;
    b[o..o+6].copy_from_slice(mac); o += 6;
    b[o..o+4].copy_from_slice(&GW_IP); o += 4;
    f.len = o as u16;
    f
}

/// Write a TCP frame into `buf`. Returns the total frame length.
/// Header layout: [virtio_net_hdr 12B][Eth 14B][IP 20B][TCP 20B][payload]
// ---- Family-aware TCP reply builders ----------------------------------------
//
// These three functions previously existed as v4/v6 pairs (eight
// functions total). The IP-header section is the only genuinely
// family-specific part — the virtio-net-hdr, Ethernet header, and
// TCP header layouts are identical between families. So we
// factored the family branch into `IpAddrPair` (above) and have
// one function each for: write-full-frame, write-headers-around-
// pre-populated-payload, and the TxFrame wrapper.

/// Write a complete TCP reply frame:
///   `[virtio_net_hdr 12 B][Eth 14 B][IP 20|40 B][TCP 20 B][payload]`
/// into `buf` starting at offset 0 and return the byte count
/// written. `addrs` selects v4 vs v6 layout + checksum form;
/// `dst_mac` is the guest MAC (we always use `GW_MAC` as source).
fn write_tcp_frame(buf: &mut [u8], dst_mac: &[u8; 6], addrs: &IpAddrPair,
    src_port: u16, dst_port: u16, seq: u32, ack: u32,
    flags: u8, payload: &[u8]) -> usize {
    let tcp_len = 20 + payload.len();
    let total = VIRTIO_NET_HDR_SIZE + 14 + addrs.ip_hdr_len() + tcp_len;
    debug_assert!(total <= buf.len());

    // virtio-net header (12 zero bytes) + Ethernet header.
    buf[..VIRTIO_NET_HDR_SIZE].fill(0);
    let mut o = VIRTIO_NET_HDR_SIZE;
    buf[o..o + 6].copy_from_slice(dst_mac); o += 6;
    buf[o..o + 6].copy_from_slice(&GW_MAC); o += 6;
    buf[o..o + 2].copy_from_slice(&addrs.ethertype().to_be_bytes()); o += 2;

    // IP header (family-specific layout + v4 csum).
    let ip_len = addrs.ip_hdr_len();
    addrs.write_ip_header(&mut buf[o..o + ip_len], tcp_len);
    o += ip_len;

    // TCP header + payload (identical layout across families).
    let ts = o;
    write_tcp_header(&mut buf[o..o + 20], src_port, dst_port, seq, ack, flags);
    o += 20;
    buf[o..o + payload.len()].copy_from_slice(payload);

    // Family-correct pseudo-header checksum over [TCP-hdr || payload].
    let cksum = addrs.tcp_checksum(&buf[ts..ts + tcp_len]);
    buf[ts + 16..ts + 18].copy_from_slice(&cksum.to_be_bytes());
    total
}

/// Like `write_tcp_frame` but the payload is already at
/// `buf[hdr_total..hdr_total+payload_len]` (read(2) dropped it
/// straight into guest RAM). Only the prefix headers are written
/// here, then the TCP checksum is patched over header + payload.
/// Returns total frame length.
fn write_tcp_frame_around_payload(buf: *mut u8, dst_mac: &[u8; 6],
    addrs: &IpAddrPair, src_port: u16, dst_port: u16,
    seq: u32, ack: u32, flags: u8, payload_len: usize) -> usize {
    let tcp_len = 20 + payload_len;
    let hdr_total = VIRTIO_NET_HDR_SIZE + 14 + addrs.ip_hdr_len() + 20;
    let total = hdr_total + payload_len;
    // Write headers via a scoped slice over the prefix region only;
    // payload bytes live past it and were placed there by the
    // caller's read(2). SAFETY: caller guarantees `buf[..hdr_total
    // + payload_len]` is a valid mutable region in guest RAM.
    let prefix = unsafe { std::slice::from_raw_parts_mut(buf, hdr_total) };
    write_tcp_headers_only(prefix, dst_mac, addrs, src_port, dst_port,
                           seq, ack, flags, tcp_len);
    // Patch the TCP checksum over [TCP-hdr || payload].
    let tcp_start = VIRTIO_NET_HDR_SIZE + 14 + addrs.ip_hdr_len();
    let tcp_seg = unsafe { std::slice::from_raw_parts(buf.add(tcp_start), tcp_len) };
    let tc = addrs.tcp_checksum(tcp_seg);
    unsafe {
        *buf.add(tcp_start + 16) = (tc >> 8) as u8;
        *buf.add(tcp_start + 17) = (tc & 0xff) as u8;
    }
    total
}

/// Write the TCP-only header (20 B) at `buf[..20]`, leaving the
/// checksum field zeroed for the caller to patch once payload is
/// in place.
#[inline]
fn write_tcp_header(buf: &mut [u8], src_port: u16, dst_port: u16,
                    seq: u32, ack: u32, flags: u8) {
    buf[0..2].copy_from_slice(&src_port.to_be_bytes());
    buf[2..4].copy_from_slice(&dst_port.to_be_bytes());
    buf[4..8].copy_from_slice(&seq.to_be_bytes());
    buf[8..12].copy_from_slice(&ack.to_be_bytes());
    buf[12] = 0x50;
    buf[13] = flags;
    buf[14..16].copy_from_slice(&0xffffu16.to_be_bytes());
    buf[16..20].fill(0); // checksum + urgent ptr (csum patched by caller)
}

/// Write `[virtio_net_hdr | Eth | IP | TCP]` into `buf[..hdr_total]`,
/// with the TCP checksum left as zero. Caller patches the
/// checksum once the payload is in place.
fn write_tcp_headers_only(buf: &mut [u8], dst_mac: &[u8; 6],
                          addrs: &IpAddrPair, src_port: u16, dst_port: u16,
                          seq: u32, ack: u32, flags: u8, tcp_len: usize) {
    buf[..VIRTIO_NET_HDR_SIZE].fill(0);
    let mut o = VIRTIO_NET_HDR_SIZE;
    buf[o..o + 6].copy_from_slice(dst_mac); o += 6;
    buf[o..o + 6].copy_from_slice(&GW_MAC); o += 6;
    buf[o..o + 2].copy_from_slice(&addrs.ethertype().to_be_bytes()); o += 2;
    let ip_len = addrs.ip_hdr_len();
    addrs.write_ip_header(&mut buf[o..o + ip_len], tcp_len);
    o += ip_len;
    write_tcp_header(&mut buf[o..o + 20], src_port, dst_port, seq, ack, flags);
}

/// `TxFrame` wrapper: stack-only allocation, fills with
/// `write_tcp_frame` and returns the populated frame. Used by
/// `build_tcp_reply` to avoid heap churn on every reply.
fn build_tcp_frame_fixed(dst_mac: &[u8; 6], addrs: &IpAddrPair,
    src_port: u16, dst_port: u16, seq: u32, ack: u32,
    flags: u8, payload: &[u8]) -> TxFrame {
    let mut f = TxFrame { data: [0u8; MAX_REPLY_FRAME], len: 0 };
    f.len = write_tcp_frame(&mut f.data, dst_mac, addrs,
        src_port, dst_port, seq, ack, flags, payload) as u16;
    f
}

/// Family-aware reply-frame builder. Both `GW_*`/`VM_*` constants
/// and `GUEST_MAC` are runner-fixed, so the family alone fully
/// determines which addressing pair to use.
fn build_tcp_reply(family: IpFamily,
    src_port: u16, dst_port: u16, seq: u32, ack: u32,
    flags: u8, payload: &[u8]) -> TxFrame {
    let addrs = match family {
        IpFamily::V4 => IpAddrPair::V4 { src: GW_IP, dst: VM_IP },
        IpFamily::V6 => IpAddrPair::V6 { src: GW_IPV6, dst: VM_IPV6 },
    };
    build_tcp_frame_fixed(&GUEST_MAC, &addrs, src_port, dst_port,
                          seq, ack, flags, payload)
}

/// Build a guest-bound UDP frame using the saved outbound-NAT
/// destination as the apparent source. Used by the outbound-UDP
/// reply drain to synthesise replies the guest's IP stack will
/// accept (matching the original destination 4-tuple).
fn build_udp_frame_in(dst_mac: &[u8; 6],
    src_ip: [u8; 4], src_port: u16,
    guest_dst_port: u16, payload: &[u8]) -> TxFrame {
    let mut f = TxFrame { data: [0u8; MAX_REPLY_FRAME], len: 0, };
    f.len = build_udp_frame(&mut f.data, dst_mac,
        src_ip, VM_IP, src_port, guest_dst_port, payload) as u16;
    f
}

/// Build a UDP frame: [virtio_net_hdr 12B][Eth 14B][IP 20B][UDP 8B][payload].
/// Returns total frame length written into `buf`.
fn build_udp_frame(buf: &mut [u8], dst_mac: &[u8; 6],
    src_ip: [u8; 4], dst_ip: [u8; 4],
    src_port: u16, dst_port: u16, payload: &[u8]) -> usize {
    let udp_len = 8 + payload.len();
    let ip_total = 20 + udp_len;
    let total = VIRTIO_NET_HDR_SIZE + 14 + ip_total;
    debug_assert!(total <= buf.len());

    // Virtio-net header (12 zero bytes).
    buf[..VIRTIO_NET_HDR_SIZE].fill(0);
    let mut o = VIRTIO_NET_HDR_SIZE;

    // Ethernet header.
    buf[o..o+6].copy_from_slice(dst_mac); o += 6;
    buf[o..o+6].copy_from_slice(&GW_MAC); o += 6;
    buf[o..o+2].copy_from_slice(&0x0800u16.to_be_bytes()); o += 2;

    // IPv4 header.
    let is = o;
    buf[o] = 0x45; buf[o+1] = 0; o += 2;
    buf[o..o+2].copy_from_slice(&(ip_total as u16).to_be_bytes()); o += 2;
    buf[o..o+4].copy_from_slice(&[0,0,0x40,0]); o += 4; // id=0, DF, frag=0
    buf[o] = 64; buf[o+1] = 17; o += 2; // TTL=64, protocol=UDP
    buf[o..o+2].fill(0); o += 2; // checksum placeholder
    buf[o..o+4].copy_from_slice(&src_ip); o += 4;
    buf[o..o+4].copy_from_slice(&dst_ip); o += 4;
    let cs = ipv4_checksum(&buf[is..is+20]);
    buf[is+10] = (cs >> 8) as u8; buf[is+11] = (cs & 0xff) as u8;

    // UDP header.
    let us = o;
    buf[o..o+2].copy_from_slice(&src_port.to_be_bytes()); o += 2;
    buf[o..o+2].copy_from_slice(&dst_port.to_be_bytes()); o += 2;
    buf[o..o+2].copy_from_slice(&(udp_len as u16).to_be_bytes()); o += 2;
    buf[o..o+2].fill(0); o += 2; // checksum placeholder
    buf[o..o+payload.len()].copy_from_slice(payload);
    let uc = udp_checksum(&src_ip, &dst_ip, &buf[us..us+udp_len]);
    buf[us+6] = (uc >> 8) as u8; buf[us+7] = (uc & 0xff) as u8;

    total
}

fn udp_checksum(si: &[u8; 4], di: &[u8; 4], seg: &[u8]) -> u16 {
    let mut s: u32 = 0;
    s += ((si[0] as u32)<<8)|si[1] as u32; s += ((si[2] as u32)<<8)|si[3] as u32;
    s += ((di[0] as u32)<<8)|di[1] as u32; s += ((di[2] as u32)<<8)|di[3] as u32;
    s += 17; // protocol = UDP
    s += seg.len() as u32;
    let mut i = 0;
    while i+1 < seg.len() { s += ((seg[i] as u32)<<8)|seg[i+1] as u32; i += 2; }
    if i < seg.len() { s += (seg[i] as u32) << 8; }
    while s >> 16 != 0 { s = (s & 0xffff) + (s >> 16); }
    let r = !(s as u16);
    // UDP checksum of 0x0000 is transmitted as 0xFFFF (RFC 768).
    if r == 0 { 0xffff } else { r }
}

fn ipv4_checksum(h: &[u8]) -> u16 {
    let mut s: u32 = 0; let mut i = 0;
    while i+1 < h.len() { s += ((h[i] as u32) << 8) | h[i+1] as u32; i += 2; }
    if i < h.len() { s += (h[i] as u32) << 8; }
    while s >> 16 != 0 { s = (s & 0xffff) + (s >> 16); } !(s as u16)
}

fn tcp_checksum(si: &[u8; 4], di: &[u8; 4], seg: &[u8]) -> u16 {
    let mut s: u32 = 0;
    s += ((si[0] as u32)<<8)|si[1] as u32; s += ((si[2] as u32)<<8)|si[3] as u32;
    s += ((di[0] as u32)<<8)|di[1] as u32; s += ((di[2] as u32)<<8)|di[3] as u32;
    s += 6; s += seg.len() as u32; let mut i = 0;
    while i+1 < seg.len() { s += ((seg[i] as u32)<<8)|seg[i+1] as u32; i += 2; }
    if i < seg.len() { s += (seg[i] as u32) << 8; }
    while s >> 16 != 0 { s = (s & 0xffff) + (s >> 16); } !(s as u16)
}
