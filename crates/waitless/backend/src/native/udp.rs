// crates/waitless/backend/src/native/udp.rs — POSIX UDP backend.
//
// Server-style binds use SO_REUSEPORT siblings (one fd per worker
// thread; kernel distributes inbound by 4-tuple hash). Owner-pinned
// ephemerals open a single fd on the owning worker. Send and drain
// dispatch use the per-thread fast-path tables maintained on
// `ThreadState` (`udp_send_fd`, `udp_dispatch`); see `super::*`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::Ordering;

use super::*;

// ============================================================================
// UDP support
// ============================================================================
//
// Two routing modes (mirroring the runtime's `UdpSocket::bind` /
// `UdpSocket::open_ephemeral` split):
//
// * **Server fanout** (`owner_worker == None`): open one
//   SO_REUSEPORT sibling per worker; the kernel distributes
//   inbound datagrams across siblings by 4-tuple hash. Replies
//   use the receiving thread's own sibling fd so the source port
//   stays equal to the bind port (NAT-correct) without
//   cross-thread socket contention.
//
// * **Single-owner ephemeral** (`owner_worker == Some(w)`): open
//   exactly one socket on worker `w`. Every reply lands on `w`'s
//   event queue.
//
// Hot-path lookups (send + drain dispatch) use per-thread tables
// allocated in `ThreadState::init_udp_tables`, not this global
// `UdpBinding` table — this map is consulted only by
// `udp_backend_unbind` to enumerate which fds to close. So the
// `Mutex<HashMap>` here is uncontended on the data path even at
// thousands of concurrent ephemeral binds.

/// One UDP relay's metadata: which workers hold which fds.
struct UdpBinding {
    /// `fds[i]` is the fd registered with worker `i`'s event
    /// queue, or `-1` for workers with no sibling. For the
    /// single-owner model only `fds[owner]` is non-negative.
    fds: [i32; MAX_THREADS],
}

fn udp_bindings() -> &'static Mutex<HashMap<u16, UdpBinding>> {
    static UDP_BINDINGS: OnceLock<Mutex<HashMap<u16, UdpBinding>>> = OnceLock::new();
    UDP_BINDINGS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Open one non-blocking UDP socket on `bind_port`. When
/// `reuseport` is set the socket joins the SO_REUSEPORT group on
/// that port (used for the fanout model, where N siblings share
/// the port and the kernel distributes inbound by 4-tuple hash);
/// otherwise it claims the port exclusively (used for
/// `bind_ephemeral`, single-owner model).
fn open_udp_sibling(bind_port: u16, reuseport: bool) -> i32 {
    unsafe {
        let fd = socket(AF_INET, SOCK_DGRAM, 0);
        if fd < 0 {
            return -1;
        }

        let opt: i32 = 1;
        if reuseport {
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, 4);
            setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, 4);
        }

        let addr = SockAddrIn {
            #[cfg(target_os = "macos")]
            sin_len: std::mem::size_of::<SockAddrIn>() as u8,
            #[cfg(target_os = "macos")]
            sin_family: AF_INET as u8,
            #[cfg(target_os = "linux")]
            sin_family: AF_INET as u16,
            sin_port: bind_port.to_be(),
            sin_addr: 0,
            sin_zero: [0; 8],
        };

        if bind(fd, &addr, std::mem::size_of::<SockAddrIn>() as u32) < 0 {
            close(fd);
            return -1;
        }

        set_nonblocking(fd);
        fd
    }
}

/// Hook registered with `executor::reactor::register_backend_bind`.
/// Invoked when a `UdpSocket` is created; opens the SO_REUSEPORT
/// siblings and routes inbound datagrams through the async
/// reactor via `executor::reactor::deliver_udp`.
///
/// `owner_worker == None`: open NUM_THREADS SO_REUSEPORT siblings
/// (the fanout / `UdpSocket::run` model — kernel distributes by
/// 4-tuple hash across per-worker recv loops).
///
/// `owner_worker == Some(w)`: open exactly one socket on worker
/// `w`'s kqueue, no SO_REUSEPORT (the `bind_ephemeral` /
/// gateway-conn model — every reply lands on `w`).
pub(super) fn udp_backend_bind(port: u16, owner_worker: Option<u32>) -> Result<(), ()> {
    open_udp_relay(port, owner_worker)
}

/// Hook registered with `register_backend_udp_unbind`. Closes
/// every sibling fd opened for `app_port`, clears the per-thread
/// fast-path tables, and removes the binding from the global map.
pub(super) fn udp_backend_unbind(app_port: u16) {
    let binding = match udp_bindings().lock().unwrap().remove(&app_port) {
        Some(b) => b,
        None => return,
    };
    let threads = unsafe { &*THREADS.0.get() };
    for (worker_id, &fd) in binding.fds.iter().enumerate() {
        if fd < 0 {
            continue;
        }
        threads[worker_id].remove_udp_binding(fd, app_port);
        unsafe {
            close(fd);
        }
    }
}

/// Open SO_REUSEPORT siblings (or one owner-pinned socket) for
/// `app_port` and publish the fds into the per-thread fast-path
/// tables. Returns `Err(())` if the OS refused the first bind —
/// higher layers surface that as `UdpBindError::BackendFailed`.
fn open_udp_relay(app_port: u16, owner_worker: Option<u32>) -> Result<(), ()> {
    // Per-port override keyed on the app's requested port:
    // `WAITLESS_UDP_<port>` swaps in a different host-bind port.
    let bind_port = read_port_env("UDP", app_port).unwrap_or(app_port);

    let mut fds = [-1i32; MAX_THREADS];
    match owner_worker {
        None => {
            // Server fanout: NUM_THREADS SO_REUSEPORT siblings.
            let want = NUM_THREADS.load(Ordering::Acquire).max(1);
            for (i, fd_slot) in fds.iter_mut().enumerate().take(want) {
                let fd = open_udp_sibling(bind_port, true);
                if fd < 0 {
                    if i == 0 {
                        return Err(());
                    }
                    break;
                }
                *fd_slot = fd;
            }
        }
        Some(w) => {
            // Single-owner: one socket on the owning worker.
            let w = w as usize;
            if w >= MAX_THREADS {
                return Err(());
            }
            let fd = open_udp_sibling(bind_port, false);
            if fd < 0 {
                return Err(());
            }
            fds[w] = fd;
        }
    }

    // Publish into the global metadata map (used only by unbind to
    // enumerate which fds to close).
    udp_bindings()
        .lock()
        .unwrap()
        .insert(app_port, UdpBinding { fds });

    // Wire up per-thread fast-path tables + event queues.
    let threads = unsafe { &*THREADS.0.get() };
    for (worker_id, &fd) in fds.iter().enumerate() {
        if fd >= 0 {
            threads[worker_id].add_udp_binding(fd, app_port);
        }
    }
    Ok(())
}

pub(super) fn udp_send(dst_ip: executor::ip::IpAddr, src_port: u16, dst_port: u16, data: &[u8]) {
    // Native backend is IPv4-only — IPv6 destinations require a
    // separate sockaddr_in6 + AF_INET6 socket; not implemented for
    // the host-side test runner. Drop silently.
    let dst_ip = match dst_ip {
        executor::ip::IpAddr::V4(a) => a.octets(),
        executor::ip::IpAddr::V6(_) => return,
    };
    unsafe {
        // Handler runs inline on a worker thread after its kqueue
        // reported the sibling ready. Reply on that worker's own
        // sibling — same kernel socket lock as the recv, and the
        // source port is already equal to the relay port, which keeps
        // NAT path-correct.
        let tid = platform::current_worker() as usize;
        // O(1) port → fd lookup via the per-thread sparse table.
        // Falls back to opening a fresh ephemeral socket if no
        // binding exists for `src_port` (e.g. send-without-bind
        // patterns the tests exercise).
        let threads = &*THREADS.0.get();
        let mut send_fd = -1;
        if tid < MAX_THREADS {
            let table = threads[tid].udp_send_fd.load(Ordering::Acquire);
            if !table.is_null() {
                let entry = &*table.add(src_port as usize);
                let v = entry.load(Ordering::Relaxed);
                if v >= 0 {
                    send_fd = v;
                }
            }
        }
        if send_fd < 0 {
            // No binding — create ephemeral socket
            send_fd = socket(AF_INET, SOCK_DGRAM, 0);
            if send_fd < 0 {
                return;
            }
        }

        let dst_addr = SockAddrIn {
            #[cfg(target_os = "macos")]
            sin_len: std::mem::size_of::<SockAddrIn>() as u8,
            #[cfg(target_os = "macos")]
            sin_family: AF_INET as u8,
            #[cfg(target_os = "linux")]
            sin_family: AF_INET as u16,
            sin_port: dst_port.to_be(),
            // sin_addr is stored in network byte order in memory.
            // `from_ne_bytes(dst_ip)` produces a u32 whose memory
            // representation matches `dst_ip` byte-for-byte on any
            // host endianness — i.e., bytes 7F 00 00 01 for
            // 127.0.0.1. Using `from_be_bytes` here would write
            // 01 00 00 7F on LE hosts and silently send to
            // 1.0.0.127 instead.
            sin_addr: u32::from_ne_bytes(dst_ip),
            sin_zero: [0; 8],
        };

        sendto(
            send_fd,
            data.as_ptr(),
            data.len(),
            0,
            &dst_addr,
            std::mem::size_of::<SockAddrIn>() as u32,
        );
    }
}
