// tools/hvf-runner/src/userspace_net/inbound.rs — host -> guest
// packet path: listener threads, flow hashing, RX-ring frame
// injection.
//
// Split out of the former monolithic `userspace_net.rs`; see
// `mod.rs` for the module overview and the FFI SAFETY contract
// that every `unsafe { libc::* }` site relies on.

use std::sync::atomic::Ordering;

use crate::virtio;

use super::*;
use super::frame::*;

// ============================================================================
// UDP listener thread
// ============================================================================
//
// One dedicated thread does `recvfrom` on every host UDP fd
// (registered v4 + v6 relays), 4-tuple-hashes the inbound flow
// to a vCPU, builds the `[virtio_hdr | Eth | IP | UDP]` frame,
// and pushes it onto that vCPU's `forwarded_rx` mailbox.
//
// Why a dedicated listener vs the previous "every vCPU races on
// recvfrom" pattern:
//
//   - macOS serialises `recvfrom` on a UDP socket via the socket
//     receive lock anyway. The N-vCPU race never extracted real
//     parallelism — it just shuffled who happened to win each
//     packet.
//
//   - The race produced multi-producer mutex contention on
//     every vCPU's `forwarded_rx` (any of N-1 vCPUs could push a
//     forwarded frame at any moment). At 4c the bench showed
//     this as a regression vs 2c (`h3_diagnostics_max` 7.3K → 5.9K).
//
//   - With one writer the per-vCPU mailbox is effectively SPSC;
//     the Mutex is uncontested in steady state and 4c scales as
//     intended.
//
// The vCPU poll loop is now smaller too: no more polling N UDP
// fds per iteration, no more `handle_udp_rx` call site. vCPUs
// just drain their `forwarded_rx` at the top of each iteration
// (the existing drain loop, unchanged).
//
// Production gVNIC is unaffected — there is no HVF runner on
// the deploy path, and Linux SO_REUSEPORT does proper 4-tuple
// hashing in-kernel.

/// One UDP fd registered with the listener. Built from
/// `UDP_RELAYS` + `UDP_RELAYS_V6` at thread start.
pub(super) struct ListenerFd {
    fd: i32,
    guest_port: u16,
    family: IpFamily,
}

/// Spawn the listener thread. Called once from `start()` after
/// `UDP_RELAYS`, `UDP_RELAYS_V6`, `WORKERS`, `VCPU_WAKE_PIPES`,
/// and `CPU_COUNT` are populated.
pub(super) fn spawn_udp_listener() {
    // Snapshot the relay tables onto Vec<ListenerFd>. Both tables
    // are publish-once OnceLocks set before this thread starts, so
    // a one-time snapshot is sound and avoids re-reading them on
    // every loop iteration.
    let mut fds: Vec<ListenerFd> = Vec::new();
    if let Some(v4) = UDP_RELAYS.get() {
        for r in v4 {
            // The fds vector inside UdpRelayFds duplicates the
            // single open fd cpu_count times for legacy reasons
            // (it was per-sibling under the old SO_REUSEPORT
            // design). Pick the first; they're all the same fd.
            if let Some(&fd) = r.fds.first() {
                fds.push(ListenerFd {
                    fd,
                    guest_port: r.guest_port,
                    family: IpFamily::V4,
                });
            }
        }
    }
    if let Some(v6) = UDP_RELAYS_V6.get() {
        for r in v6 {
            if let Some(&fd) = r.fds.first() {
                fds.push(ListenerFd {
                    fd,
                    guest_port: r.guest_port,
                    family: IpFamily::V6,
                });
            }
        }
    }

    if fds.is_empty() {
        return;
    }

    std::thread::Builder::new()
        .name("hvf-udp-listener".into())
        .spawn(move || udp_listener_loop(fds))
        .expect("hvf-udp-listener thread spawn");
}

/// Listener main loop: poll all UDP fds, drain ready ones, hash
/// + dispatch each datagram to the owning vCPU's `forwarded_rx`.
pub(super) fn udp_listener_loop(fds: Vec<ListenerFd>) {
    let cpu_count = CPU_COUNT.load(Ordering::Relaxed);
    let mut read_buf = vec![0u8; 65536];
    let mut frame_buf = vec![0u8; 2048];
    let mut pollfds: Vec<libc::pollfd> = fds
        .iter()
        .map(|f| libc::pollfd {
            fd: f.fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();

    loop {
        // Poll with a 1-second timeout. The poll itself has no
        // direct cost on the runner — the thread is otherwise
        // idle — so a long timeout is fine. The wake-on-event
        // path is the kernel's: a single packet arrival wakes
        // poll instantly.
        let ready = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as u32, 1000) };
        if ready <= 0 {
            continue;
        }

        for (i, f) in fds.iter().enumerate() {
            if pollfds[i].revents & libc::POLLIN == 0 {
                continue;
            }
            // Reset for next poll iteration.
            pollfds[i].revents = 0;
            match f.family {
                IpFamily::V4 => {
                    listener_drain_v4(f.fd, f.guest_port, cpu_count, &mut read_buf, &mut frame_buf)
                }
                IpFamily::V6 => {
                    listener_drain_v6(f.fd, f.guest_port, cpu_count, &mut read_buf, &mut frame_buf)
                }
            }
        }
    }
}

/// Drain a v4 UDP fd: recvfrom in a loop until EAGAIN, hashing
/// each datagram to a vCPU and forwarding the built frame.
pub(super) fn listener_drain_v4(
    fd: i32,
    guest_port: u16,
    cpu_count: usize,
    read_buf: &mut [u8],
    frame_buf: &mut [u8],
) {
    loop {
        let mut client_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut addr_len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in>() as u32;
        let n = unsafe {
            libc::recvfrom(
                fd,
                read_buf.as_mut_ptr() as *mut _,
                read_buf.len(),
                0,
                &mut client_addr as *mut _ as *mut libc::sockaddr,
                &mut addr_len,
            )
        };
        if n <= 0 {
            break;
        }
        let payload_len = n as usize;
        let client_port = u16::from_be(client_addr.sin_port);
        let client_ip = u32::from_be(client_addr.sin_addr.s_addr);

        let target = target_vcpu_v4(client_ip, client_port, guest_port, cpu_count);

        // Reply-path NAT map lives on the OWNING vCPU so when the
        // guest sends a UDP reply the matching vCPU's
        // `handle_udp_v4` finds the right sockaddr.
        {
            let mut m = worker_shared(target).udp_clients.lock().unwrap();
            m.insert((guest_port, client_port), client_addr);
        }

        let frame_len = build_udp_frame_v4(
            frame_buf,
            &GUEST_MAC,
            GW_IP,
            VM_IP,
            client_port,
            guest_port,
            &read_buf[..payload_len],
        );
        forward_frame_to_vcpu(target, &frame_buf[..frame_len]);
    }
}

/// IPv6 counterpart to [`listener_drain_v4`].
pub(super) fn listener_drain_v6(
    fd: i32,
    guest_port: u16,
    cpu_count: usize,
    read_buf: &mut [u8],
    frame_buf: &mut [u8],
) {
    loop {
        let mut client_addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut addr_len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in6>() as u32;
        let n = unsafe {
            libc::recvfrom(
                fd,
                read_buf.as_mut_ptr() as *mut _,
                read_buf.len(),
                0,
                &mut client_addr as *mut _ as *mut libc::sockaddr,
                &mut addr_len,
            )
        };
        if n <= 0 {
            break;
        }
        let payload_len = n as usize;
        let client_port = u16::from_be(client_addr.sin6_port);

        let target = target_vcpu_v6(
            &client_addr.sin6_addr.s6_addr,
            client_port,
            guest_port,
            cpu_count,
        );
        {
            let mut m = worker_shared(target).udp_clients_v6.lock().unwrap();
            m.insert((guest_port, client_port), client_addr);
        }

        let frame_len = build_udp_frame_v6(
            frame_buf,
            &GUEST_MAC,
            &GW_IPV6,
            &VM_IPV6,
            client_port,
            guest_port,
            &read_buf[..payload_len],
        );
        forward_frame_to_vcpu(target, &frame_buf[..frame_len]);
    }
}

/// FNV-1a 32-bit hash of bytes. Cheap, deterministic, and good
/// enough distribution for picking a vCPU index from a UDP
/// 4-tuple.
pub(super) fn fnv1a_32(bytes: &[u8]) -> u32 {
    let mut h: u32 = 2166136261;
    for &b in bytes {
        h ^= b as u32;
        h = h.wrapping_mul(16777619);
    }
    h
}

/// Pick the owning vCPU for a UDP IPv4 flow. Same 4-tuple always
/// hashes to the same vCPU, giving stateful protocols (QUIC) the
/// flow affinity that a 4-tuple-hashing kernel SO_REUSEPORT would
/// give for free. macOS UDP shared-fd recv distributes by
/// recvfrom race — so we recover affinity by routing in user
/// space after the recv.
pub(super) fn target_vcpu_v4(client_ip: u32, client_port: u16, guest_port: u16, cpu_count: usize) -> usize {
    if cpu_count <= 1 {
        return 0;
    }
    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&client_ip.to_be_bytes());
    buf[4..6].copy_from_slice(&client_port.to_be_bytes());
    buf[6..8].copy_from_slice(&guest_port.to_be_bytes());
    (fnv1a_32(&buf) as usize) % cpu_count
}

/// IPv6 counterpart to [`target_vcpu_v4`]. Hashes the 16-byte
/// client address + ports.
pub(super) fn target_vcpu_v6(
    client_ip: &[u8; 16],
    client_port: u16,
    guest_port: u16,
    cpu_count: usize,
) -> usize {
    if cpu_count <= 1 {
        return 0;
    }
    let mut buf = [0u8; 20];
    buf[0..16].copy_from_slice(client_ip);
    buf[16..18].copy_from_slice(&client_port.to_be_bytes());
    buf[18..20].copy_from_slice(&guest_port.to_be_bytes());
    (fnv1a_32(&buf) as usize) % cpu_count
}

/// Push a built Ethernet frame onto the target vCPU's
/// `forwarded_rx` mailbox and wake it. The target vCPU drains
/// the mailbox at the top of its next `vcpu_poll` and injects
/// each frame into its own RX queue.
///
/// Wake-coalescing: only wake when the mailbox transitions
/// empty → non-empty. If frames were already queued, the vCPU is
/// either currently draining or about to (its next poll
/// iteration will see them naturally), so a wake is redundant.
/// Saves one `write(wake_pipe) + vm::wake_vcpu()` syscall pair
/// per packet when the vCPU is keeping up under burst.
pub(super) fn forward_frame_to_vcpu(target_vcpu: usize, frame: &[u8]) {
    let target_shared = worker_shared(target_vcpu);
    let need_wake = {
        let mut q = target_shared.forwarded_rx.lock().unwrap();
        let was_empty = q.is_empty();
        q.push_back(frame.to_vec());
        was_empty
    };
    if !need_wake {
        return;
    }
    if let Some(pipes) = VCPU_WAKE_PIPES.get() {
        if let Some(p) = pipes.get(target_vcpu) {
            let buf = [0u8; 1];
            unsafe {
                libc::write(p.write_fd, buf.as_ptr() as *const _, 1);
            }
        }
    }
    crate::vm::wake_vcpu(target_vcpu);
}

// `handle_udp_rx` removed — the dedicated UDP listener thread now
// owns recvfrom for every host UDP fd. See `udp_listener_loop` /
// `listener_drain_v4` upstream.

pub(super) fn inject_frame(frame: &[u8], snap: &virtio::QueueSnapshot, rx_last: &mut u16) -> bool {
    let avail_idx =
        unsafe { core::ptr::read_volatile(snap.gpa_to_host(snap.avail_addr + 2) as *const u16) };
    let last = *rx_last;
    if last == avail_idx {
        return false;
    }
    let ring_idx = last & (snap.qsize - 1);
    let desc_idx = unsafe {
        core::ptr::read_volatile(
            snap.gpa_to_host(snap.avail_addr + 4 + ring_idx as u64 * 2) as *const u16
        )
    };
    let addr = unsafe {
        core::ptr::read_unaligned(
            snap.gpa_to_host(snap.desc_addr + desc_idx as u64 * 16) as *const u64
        )
    };
    unsafe {
        core::ptr::copy_nonoverlapping(frame.as_ptr(), snap.gpa_to_host(addr), frame.len());
    }
    let used_idx =
        unsafe { core::ptr::read_volatile(snap.gpa_to_host(snap.used_addr + 2) as *const u16) };
    unsafe {
        let entry = snap.gpa_to_host(snap.used_addr + 4 + (used_idx & (snap.qsize - 1)) as u64 * 8);
        core::ptr::write_unaligned(entry as *mut u32, desc_idx as u32);
        core::ptr::write_unaligned(entry.add(4) as *mut u32, frame.len() as u32);
        core::ptr::write_volatile(
            snap.gpa_to_host(snap.used_addr + 2) as *mut u16,
            used_idx.wrapping_add(1),
        );
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

pub(super) fn inject_data_frames(
    c: &mut ProxyConn,
    data: &[u8],
    mac: &[u8; 6],
    snap: &virtio::QueueSnapshot,
    rx_last: &mut u16,
    frame_buf: &mut [u8; 2048],
) {
    let max_chunk = match c.family {
        IpFamily::V4 => 1460,
        IpFamily::V6 => 1440,
    };
    let addrs = match c.family {
        IpFamily::V4 => IpAddrPair::V4 {
            src: GW_IP,
            dst: VM_IP,
        },
        IpFamily::V6 => IpAddrPair::V6 {
            src: GW_IPV6,
            dst: VM_IPV6,
        },
    };
    let mut off = 0;
    while off < data.len() {
        let chunk = (data.len() - off).min(max_chunk);
        let len = write_tcp_frame(
            frame_buf,
            mac,
            &addrs,
            &TcpFrameSpec {
                src_port: c.src_port,
                dst_port: c.guest_port,
                seq: c.my_seq,
                ack: c.peer_ack,
                flags: 0x18,
            },
            &data[off..off + chunk],
        );
        c.my_seq = c.my_seq.wrapping_add(chunk as u32);
        off += chunk;
        inject_frame(&frame_buf[..len], snap, rx_last);
    }
}

