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
}

impl WorkerShared {
    fn new() -> Self {
        Self {
            conns: Mutex::new(HashMap::new()),
            tx_replies: Mutex::new(VecDeque::new()),
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

const GUEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

/// Per-listen-socket state.
#[derive(Clone, Copy)]
struct TcpListen {
    fd: i32,
    guest_port: u16,
}

/// One UDP-relay sibling, scoped to a single vCPU's IoState. The
/// enclosing relay opens `cpu_count` SO_REUSEPORT-bound siblings at
/// `start()` time; vCPU `N` owns sibling `N`, and `UDP_RELAYS` below
/// keeps a flat `Vec<i32>` so the TX-side `handle_udp` can still look
/// up "this vCPU's sibling" when the guest sends a reply.
#[derive(Clone, Copy)]
struct UdpRelay {
    fd: i32,
    guest_port: u16,
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
        libc::listen(fd, 128);
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

    for m in mappings {
        match m.proto {
            Proto::Tcp => {
                let fd = bind_listen(m.host)?;
                listens.push(TcpListen { fd, guest_port: m.guest });
            }
            Proto::Udp => match open_udp_sibling(m.host) {
                Ok(fd) => {
                    // One fd shared across every vCPU's pollfds.
                    for worker_id in 0..cpu_count {
                        per_worker_udps[worker_id].push(UdpRelay {
                            fd,
                            guest_port: m.guest,
                        });
                    }
                    // `relay_table.fds` is still a vec for the TX
                    // side's per-vCPU lookup, but every entry is
                    // the same shared fd.
                    let fds = vec![fd; cpu_count.max(1)];
                    relay_table.push(UdpRelayFds {
                        guest_port: m.guest,
                        fds,
                    });
                }
                // UDP bind is non-fatal — keep TCP working even if UDP port is taken.
                Err(e) => eprintln!("  warning: {e}"),
            },
        }
    }

    if !relay_table.is_empty() {
        UDP_RELAYS.set(relay_table).ok();
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
    // The bytes are just signals from the accept thread; the actual
    // new conn was already inserted into `WORKERS[id].conns` and the
    // SYN frame into `tx_replies` before the doorbell. We drain the
    // pipe here so it doesn't keep firing on subsequent polls.
    if io.pollfds[0].revents & libc::POLLIN != 0 {
        let mut tmp = [0u8; 64];
        loop {
            let n = unsafe {
                libc::read(io.wake_pipe_read, tmp.as_mut_ptr() as *mut _, tmp.len())
            };
            if n <= 0 { break; }
        }
    }

    // ── Drain UDP relay siblings that fired ────────────────────────
    {
        let udp_drain: Vec<(i32, u16)> = io.udps.iter()
            .map(|u| (u.fd, u.guest_port))
            .collect();
        for (i, (fd, gp)) in udp_drain.into_iter().enumerate() {
            if io.pollfds[udp_slot_start + i].revents & libc::POLLIN != 0 {
                handle_udp_rx(io, &qsnap, fd, gp, single_queue);
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
                // Flow-hash-aware src_port selection: pick a port
                // whose 4-tuple hashes to the current vCPU's bucket
                // under the guest's `net/lib.rs::flow_hash`. That
                // keeps the conn on a single core end-to-end —
                // without it, ~(cpu_count-1)/cpu_count of accepted
                // connections would land on one guest core and
                // bounce to another via the SPSC `rx_inbox` on
                // every packet.
                let src_port = alloc_src_port_for_vcpu(
                    io.id, cpu_count, listen.guest_port,
                );
                let frame = build_tcp_frame_fixed(
                    &GUEST_MAC, GW_IP, VM_IP,
                    src_port, listen.guest_port, 1000, 0, 0x02, &[],
                );
                shared.tx_replies.lock().unwrap().push_back(frame);
                shared.conns.lock().unwrap().insert(src_port, ProxyConn {
                    host_fd: client_fd, src_port, guest_port: listen.guest_port,
                    my_seq: 1001, peer_ack: 0,
                    state: ConnState::SynSent, pending: Vec::new(),
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

    // ── Zero-copy RX from established TCP conns ────────────────────
    const HDR_LEN: usize = VIRTIO_NET_HDR_SIZE + 14 + 20 + 20;
    const MAX_PAYLOAD: usize = 1460;
    struct ConnSnap { port: u16, guest_port: u16, fd: i32, seq: u32, ack: u32 }

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
                                seq: c.my_seq, ack: c.peer_ack,
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

            let payload_ptr = unsafe { guest_buf.add(HDR_LEN) };
            let n = unsafe { libc::read(cs.fd, payload_ptr as *mut _, MAX_PAYLOAD) };
            if n <= 0 {
                if n == 0 {
                    results.push(RxResult { port: cs.port, seq_advance: 0, eof: true });
                }
                continue;
            }
            let payload_len = n as usize;

            let total = write_tcp_frame_around_payload(
                guest_buf, &GUEST_MAC, GW_IP, VM_IP,
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
                        let frame = build_tcp_frame_fixed(&GUEST_MAC, GW_IP, VM_IP,
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
    let mut off = 0;
    while off < data.len() {
        let chunk = (data.len() - off).min(1460);
        let len = write_tcp_frame(frame_buf, mac, GW_IP, VM_IP, c.src_port, c.guest_port,
            c.my_seq, c.peer_ack, 0x18, &data[off..off + chunk]);
        c.my_seq = c.my_seq.wrapping_add(chunk as u32);
        off += chunk;
        inject_frame(&frame_buf[..len], snap, rx_last);
    }
}


// ── Guest TX (vCPU thread) ──────────────────────────────────────────────────

fn handle_guest_tx(frame: &[u8]) {
    if frame.len() < 14 { return; }
    match u16::from_be_bytes([frame[12], frame[13]]) {
        0x0806 => handle_arp(&frame[14..]),
        0x0800 => handle_ipv4(&frame[14..]),
        _ => {}
    }
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
    match ip[9] { 6 => handle_tcp(&ip[ihl..]), 17 => handle_udp(&ip[ihl..]), _ => {} }
}

fn handle_tcp(tcp: &[u8]) {
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
                let f = build_tcp_frame_fixed(&GUEST_MAC, GW_IP, VM_IP,
                    snap.port, snap.guest_port, snap.seq, ack, 0x10, &[]);
                replies.push_back(f);
            }
        }
        ConnState::Established => {
            if !payload.is_empty() {
                let ack = seq.wrapping_add(payload.len() as u32);
                let f = build_tcp_frame_fixed(&GUEST_MAC, GW_IP, VM_IP,
                    snap.port, src_port, snap.seq, ack, 0x10, &[]);
                replies.push_back(f);
            }
            if flags & 0x01 != 0 {
                let ack = snap.ack.wrapping_add(1);
                let f = build_tcp_frame_fixed(&GUEST_MAC, GW_IP, VM_IP,
                    snap.port, src_port, snap.seq, ack, 0x11, &[]);
                replies.push_back(f);
            }
        }
        _ => {}
    }
}

fn handle_udp(udp: &[u8]) {
    if udp.len() < 8 { return; }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    // DHCP: guest port 68 → server port 67.
    if src_port == 68 && dst_port == 67 {
        handle_dhcp(&udp[8..]);
        return;
    }
    // General UDP relay: guest → external client.
    //
    // The guest's frame has src_port=<guest-side listener> (matches the
    // GUEST in one of our `-p udp:HOST:GUEST` mappings) and
    // dst_port=<client ephemeral>. Pick the TX fd for the current vCPU
    // from the relay's SO_REUSEPORT pool so multi-core TX doesn't
    // serialise on a shared kernel socket lock. The TX siblings are all
    // bound to the same host port, so packet source port == relay port
    // — NAT-correct.
    let payload = &udp[8..];
    if payload.is_empty() { return; }
    let vcpu_id = CURRENT_VCPU.with(|c| c.get());
    let fd = match UDP_RELAYS.get() {
        Some(table) => {
            let relay = match table.iter().find(|r| r.guest_port == src_port) {
                Some(r) => r,
                None => return,
            };
            // Per-vCPU sibling fd; fall back to sibling 0 if the
            // vCPU id is out of range (shouldn't happen).
            match relay.fds.get(vcpu_id).or_else(|| relay.fds.first()) {
                Some(&fd) => fd,
                None => return,
            }
        }
        None => return,
    };
    // The UDP client-addr map is per-worker and our paired worker is
    // the only producer, so this vCPU's worker-local map is exactly
    // where the return-path entry was written.
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
fn write_tcp_frame(buf: &mut [u8], dst_mac: &[u8; 6], src_ip: [u8; 4], dst_ip: [u8; 4],
    src_port: u16, dst_port: u16, seq: u32, ack: u32,
    flags: u8, payload: &[u8]) -> usize {
    let tcp_len = 20 + payload.len();
    let ip_total = 20 + tcp_len;
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
    buf[o..o+4].copy_from_slice(&[0,0,0x40,0]); o += 4;
    buf[o] = 64; buf[o+1] = 6; o += 2;
    buf[o..o+2].fill(0); o += 2; // checksum placeholder
    buf[o..o+4].copy_from_slice(&src_ip); o += 4;
    buf[o..o+4].copy_from_slice(&dst_ip); o += 4;
    let cs = ipv4_checksum(&buf[is..is+20]);
    buf[is+10] = (cs >> 8) as u8; buf[is+11] = (cs & 0xff) as u8;

    // TCP header.
    let ts = o;
    buf[o..o+2].copy_from_slice(&src_port.to_be_bytes()); o += 2;
    buf[o..o+2].copy_from_slice(&dst_port.to_be_bytes()); o += 2;
    buf[o..o+4].copy_from_slice(&seq.to_be_bytes()); o += 4;
    buf[o..o+4].copy_from_slice(&ack.to_be_bytes()); o += 4;
    buf[o] = 0x50; buf[o+1] = flags; o += 2;
    buf[o..o+2].copy_from_slice(&0xffffu16.to_be_bytes()); o += 2;
    buf[o..o+4].fill(0); o += 4; // checksum + urgent ptr
    buf[o..o+payload.len()].copy_from_slice(payload);
    let tc = tcp_checksum(&src_ip, &dst_ip, &buf[ts..ts+tcp_len]);
    buf[ts+16] = (tc >> 8) as u8; buf[ts+17] = (tc & 0xff) as u8;

    total
}

/// Write TCP frame headers around payload already at buf[66..66+payload_len].
/// The payload was read() directly into guest RAM; we just write headers before it.
/// Returns total frame length.
fn write_tcp_frame_around_payload(buf: *mut u8, dst_mac: &[u8; 6],
    src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16,
    seq: u32, ack: u32, flags: u8, payload_len: usize) -> usize {
    let tcp_len = 20 + payload_len;
    let ip_total = 20 + tcp_len;
    let total = VIRTIO_NET_HDR_SIZE + 14 + ip_total;
    // Write into guest RAM via raw pointer (payload is already there).
    let b = unsafe { std::slice::from_raw_parts_mut(buf, VIRTIO_NET_HDR_SIZE + 14 + 20 + 20) };
    write_tcp_frame_headers(b, dst_mac, src_ip, dst_ip, src_port, dst_port,
        seq, ack, flags, ip_total);
    // Compute TCP checksum over header + payload.
    let tcp_start = VIRTIO_NET_HDR_SIZE + 14 + 20;
    let tcp_seg = unsafe { std::slice::from_raw_parts(buf.add(tcp_start), tcp_len) };
    let tc = tcp_checksum(&src_ip, &dst_ip, tcp_seg);
    unsafe {
        *buf.add(tcp_start + 16) = (tc >> 8) as u8;
        *buf.add(tcp_start + 17) = (tc & 0xff) as u8;
    }
    total
}

/// Write just the headers (virtio + eth + ip + tcp) into buf[..66].
/// Does NOT write payload (caller handles that). Sets checksum placeholders.
fn write_tcp_frame_headers(buf: &mut [u8], dst_mac: &[u8; 6],
    src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16,
    seq: u32, ack: u32, flags: u8, ip_total: usize) {
    buf[..VIRTIO_NET_HDR_SIZE].fill(0);
    let mut o = VIRTIO_NET_HDR_SIZE;
    buf[o..o+6].copy_from_slice(dst_mac); o += 6;
    buf[o..o+6].copy_from_slice(&GW_MAC); o += 6;
    buf[o..o+2].copy_from_slice(&0x0800u16.to_be_bytes()); o += 2;
    let is = o;
    buf[o] = 0x45; buf[o+1] = 0; o += 2;
    buf[o..o+2].copy_from_slice(&(ip_total as u16).to_be_bytes()); o += 2;
    buf[o..o+4].copy_from_slice(&[0,0,0x40,0]); o += 4;
    buf[o] = 64; buf[o+1] = 6; o += 2;
    buf[o..o+2].fill(0); o += 2;
    buf[o..o+4].copy_from_slice(&src_ip); o += 4;
    buf[o..o+4].copy_from_slice(&dst_ip); o += 4;
    let cs = ipv4_checksum(&buf[is..is+20]);
    buf[is+10] = (cs >> 8) as u8; buf[is+11] = (cs & 0xff) as u8;
    buf[o..o+2].copy_from_slice(&src_port.to_be_bytes()); o += 2;
    buf[o..o+2].copy_from_slice(&dst_port.to_be_bytes()); o += 2;
    buf[o..o+4].copy_from_slice(&seq.to_be_bytes()); o += 4;
    buf[o..o+4].copy_from_slice(&ack.to_be_bytes()); o += 4;
    buf[o] = 0x50; buf[o+1] = flags; o += 2;
    buf[o..o+2].copy_from_slice(&0xffffu16.to_be_bytes()); o += 2;
    buf[o..o+4].fill(0); // checksum + urgent (filled later)
}

/// Fixed-size frame wrapper — no heap allocation.
fn build_tcp_frame_fixed(dst_mac: &[u8; 6], src_ip: [u8; 4], dst_ip: [u8; 4],
    src_port: u16, dst_port: u16, seq: u32, ack: u32,
    flags: u8, payload: &[u8]) -> TxFrame {
    let mut f = TxFrame { data: [0u8; MAX_REPLY_FRAME], len: 0, };
    f.len = write_tcp_frame(&mut f.data, dst_mac, src_ip, dst_ip,
        src_port, dst_port, seq, ack, flags, payload) as u16;
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
