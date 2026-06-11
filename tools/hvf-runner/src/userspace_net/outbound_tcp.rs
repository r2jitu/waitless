// tools/hvf-runner/src/userspace_net/outbound_tcp.rs — guest-initiated
// outbound TCP: the proxy-side bridge that lets the guest's new active
// open (`tcp_connect`) reach real host sockets, following the
// outbound-UDP NAT pattern (`handle_udp_outbound` / `drain_outbound_udp`).
//
// Shape:
//   * Per-vCPU flow map (`IoState::outbound_tcp`), keyed by the guest
//     4-tuple's variable parts `(guest_src_port, dst_ip, dst_port)` —
//     guest src ip is always `VM_IP`. Single-owner per vCPU like
//     `outbound_udp`: the guest emits a conn's segments on the core
//     that owns it, so the same vCPU services the whole flow.
//   * No new threads: a non-blocking `connect(2)` polled for POLLOUT
//     inline in the vCPU's poll loop (the same loop that polls the
//     inbound conn fds), then POLLIN for host→guest data.
//   * State machine + seq/ack bookkeeping live in `outbound_fsm.rs`
//     (pure, unit-tested); this file only executes its verdicts.
//   * Destinations: `GW_IP` (10.0.2.2, the guest's gateway) maps to
//     host loopback — mirroring outbound UDP — and anything else is
//     dialed as-is, so LAN destinations work too. dst port 0, the
//     guest's own IP, and the proxy's own TCP listener ports (on the
//     loopback mapping) are refused with an RST.
//
// See `mod.rs` for the module overview and the FFI SAFETY contract
// every `unsafe { libc::* }` site in this file relies on.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::virtio;

use super::frame::*;
use super::inbound::*;
use super::outbound_fsm::{Ctl, FsmState, HostOp, OutboundFsm, SegOut, flow_expired, refuse_syn};
use super::*;

/// Per-vCPU cap on concurrent guest-initiated flows. Beyond this a
/// SYN draws an RST + one log line — the dev tool's analogue of an
/// ephemeral-port-exhausted host.
const MAX_OUTBOUND_TCP: usize = 64;

/// Our fixed toy ISN, mirroring the inbound peer's `my_seq: 1000`.
const OUT_ISN: u32 = 1000;

/// Largest host→guest payload per synthesized segment — same value
/// the inbound v4 data path uses (`inject_data_frames`).
const OUT_MAX_PAYLOAD: usize = 1460;

/// Cumulative guest→host bytes the best-effort non-blocking write
/// couldn't take. Same lossy-toy contract as the inbound path's
/// `HOST_WRITE_DROPPED_BYTES`: the bytes were already ACKed to the
/// guest, which won't resend. Logged loudly once.
static OUT_WRITE_DROPPED_BYTES: AtomicU64 = AtomicU64::new(0);

/// Flow key: the variable parts of the guest 4-tuple —
/// `(guest_src_port, dst_ip, dst_port)`. Distinct from the inbound
/// `conns` map (keyed by proxy pseudo-ephemeral port), so inbound
/// port-forward flows can never collide with these.
pub(super) type OutTcpKey = (u16, [u8; 4], u16);

pub(super) struct OutboundTcp {
    pub(super) fd: i32,
    pub(super) fsm: OutboundFsm,
    /// Destination exactly as the guest addressed it — reply frames
    /// are sourced from this (ip, port) so the guest's stack matches
    /// them to its conn.
    dst_ip: [u8; 4],
    dst_port: u16,
    /// The guest's ephemeral source port (reply frames' dst_port).
    guest_port: u16,
    /// Host→guest bytes read while the RX ring was unready/full;
    /// flushed (in order, ahead of any FIN) by `drain_outbound_tcp`.
    pending: Vec<u8>,
    /// Host EOF observed while `pending` was still unflushed — the
    /// FIN is deferred until the last data byte is injected so it
    /// sequences correctly.
    host_eof: bool,
    /// Last time this flow saw legitimate activity — a guest segment
    /// or a host I/O event. The periodic sweep (`mod.rs`) reaps a
    /// flow idle longer than `OUTBOUND_IDLE_TIMEOUT`, so flows whose
    /// counterparty goes silent in a never-advancing state
    /// (`SynAckSent`/`GuestClosed`/`FinWait`) can't leak toward the
    /// `MAX_OUTBOUND_TCP` cap. Refreshed via `touch()`.
    last_active: Instant,
}

impl OutboundTcp {
    /// Mark legitimate activity (a guest segment or a host I/O
    /// event), keeping the flow off the idle-sweep's reap list.
    fn touch(&mut self) {
        self.last_active = Instant::now();
    }

    /// Whether the periodic sweep should evict this flow: idle past
    /// the deadline, per the pure predicate in `outbound_fsm`. `now`
    /// is threaded in (rather than read here) so the predicate stays
    /// unit-testable with a faked clock.
    pub(super) fn expired_at(&self, now: Instant) -> bool {
        flow_expired(self.fsm.state, now.saturating_duration_since(self.last_active))
    }
}

impl OutboundTcp {
    /// Poll registration for this flow: `Some(true)` = POLLOUT
    /// (connect in flight), `Some(false)` = POLLIN (bridging), `None`
    /// = not polled. SynAckSent is deliberately not polled — reading
    /// host data before the guest's handshake ACK could inject data
    /// segments ahead of the SYN-ACK, which the guest (still in
    /// SynSent) drops, and the toy peer never retransmits. FinWait
    /// flows have `fd == -1`.
    pub(super) fn poll_wants(&self) -> Option<bool> {
        if self.fd < 0 {
            return None;
        }
        match self.fsm.state {
            FsmState::Connecting => Some(true),
            FsmState::Established | FsmState::GuestClosed => Some(false),
            FsmState::SynAckSent | FsmState::FinWait => None,
        }
    }

    /// Build a payload-less control frame for this flow, addressed
    /// from the original destination so the guest accepts it.
    fn ctl_frame(&self, ctl: &Ctl) -> TxFrame {
        build_tcp_frame_fixed(
            &GUEST_MAC,
            &IpAddrPair::V4 {
                src: self.dst_ip,
                dst: VM_IP,
            },
            &TcpFrameSpec {
                src_port: self.dst_port,
                dst_port: self.guest_port,
                seq: ctl.seq,
                ack: ctl.ack,
                flags: ctl.flags,
            },
            &[],
        )
    }
}

/// Close `*fd` (if open) and mark it gone. `rst` mirrors the inbound
/// RST branch: SO_LINGER{1,0} so `close(2)` emits RST instead of the
/// FIN-ACK dance, propagating the guest's reset to the host peer.
fn close_fd(fd: &mut i32, rst: bool) {
    if *fd < 0 {
        return;
    }
    unsafe {
        if rst {
            let linger = libc::linger {
                l_onoff: 1,
                l_linger: 0,
            };
            libc::setsockopt(
                *fd,
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &linger as *const _ as *const _,
                std::mem::size_of::<libc::linger>() as u32,
            );
        }
        libc::close(*fd);
    }
    *fd = -1;
}

/// Best-effort non-blocking write of a guest segment's payload to the
/// host socket. The payload is already ACKed to the guest (the FSM
/// advanced `peer_ack`), so a full host send buffer drops bytes —
/// same loud-once warning contract as the inbound path.
fn write_best_effort(fd: i32, payload: &[u8], guest_port: u16) {
    let mut written = 0usize;
    while written < payload.len() {
        let n = unsafe {
            libc::write(
                fd,
                payload.as_ptr().add(written) as *const _,
                payload.len() - written,
            )
        };
        if n <= 0 {
            break;
        }
        written += n as usize;
    }
    if written < payload.len() {
        let dropped = (payload.len() - written) as u64;
        let prev = OUT_WRITE_DROPPED_BYTES.fetch_add(dropped, Ordering::Relaxed);
        if prev == 0 {
            eprintln!(
                "[hvf-net] WARNING: guest outbound TCP write dropped {dropped} bytes \
                 (host send buffer full, guest port {guest_port}). Toy-proxy limit, \
                 not a guest bug."
            );
        }
    }
}

/// Execute an FSM verdict's host-socket op against `flow.fd`.
fn apply_host_op(flow: &mut OutboundTcp, op: &HostOp) {
    match op {
        HostOp::None => {}
        HostOp::ShutdownWrite => {
            if flow.fd >= 0 {
                unsafe {
                    libc::shutdown(flow.fd, libc::SHUT_WR);
                }
            }
        }
        HostOp::Close => close_fd(&mut flow.fd, false),
        HostOp::CloseRst => close_fd(&mut flow.fd, true),
    }
}

/// Periodic idle-flow reaper, called from the same `mod.rs` cleanup
/// pass that sweeps the inbound `conns` map. Evicts every outbound
/// flow idle past `OUTBOUND_IDLE_TIMEOUT` (the leak-prone
/// `SynAckSent`/`GuestClosed`/`FinWait` states never advance on their
/// own once the counterparty goes silent, so without this they pin a
/// slot toward `MAX_OUTBOUND_TCP` forever and then RST every new
/// SYN). Closes each evicted flow's host fd on the way out (same
/// `close_fd` teardown the normal `remove` path uses) so no fd leaks.
/// `now` is threaded in so the expiry decision stays a pure,
/// unit-tested predicate (`OutboundTcp::expired_at` →
/// `outbound_fsm::flow_expired`).
pub(super) fn sweep_idle(io: &mut IoState, now: Instant) {
    if io.outbound_tcp.is_empty() {
        return;
    }
    let mut reaped = 0usize;
    io.outbound_tcp.retain(|_, flow| {
        if flow.expired_at(now) {
            close_fd(&mut flow.fd, false);
            reaped += 1;
            false
        } else {
            true
        }
    });
    if reaped > 0 {
        eprintln!("[hvf-net] reaped {reaped} idle outbound TCP flow(s)");
    }
}

/// vCPU-side entry point: a guest TCP segment that matched no inbound
/// port-forward flow (or is a bare SYN, which is always an active
/// open). Called from `guest_tx::handle_tcp` with `CURRENT_VCPU` set;
/// locks this vCPU's own `IoState`, same as `handle_udp_outbound`.
pub(super) fn handle_guest_segment(dst_ip: [u8; 4], tcp: &[u8]) {
    if tcp.len() < 20 {
        return;
    }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    let flags = tcp[13];
    let payload = if tcp.len() > data_offset {
        &tcp[data_offset..]
    } else {
        &[]
    };

    let vcpu_id = CURRENT_VCPU.with(|c| c.get());
    let Some(vcpu_ios) = VCPU_IOS.get() else {
        return;
    };
    let Some(io_mutex) = vcpu_ios.get(vcpu_id) else {
        return;
    };
    let mut io = io_mutex.lock().unwrap();

    let key: OutTcpKey = (src_port, dst_ip, dst_port);
    let reply: Option<TxFrame> = if let Some(flow) = io.outbound_tcp.get_mut(&key) {
        flow.touch();
        let out = flow.fsm.on_guest_segment(seq, flags, payload.len());
        // Payload before any shutdown/close — write-then-shutdown.
        if out.write_payload && flow.fd >= 0 && !payload.is_empty() {
            write_best_effort(flow.fd, payload, src_port);
        }
        apply_host_op(flow, &out.host_op);
        let frame = out.ctl.as_ref().map(|c| flow.ctl_frame(c));
        if out.remove {
            if let Some(mut f) = io.outbound_tcp.remove(&key) {
                close_fd(&mut f.fd, false);
            }
        }
        frame
    } else if flags & (SYN_FLAG | ACK_FLAG) == SYN_FLAG {
        open_flow(&mut io, key, seq)
    } else {
        // Stray segment for an unknown (or already-reaped) flow —
        // silently dropped, mirroring the inbound path's behaviour
        // for reaped conns.
        None
    };
    drop(io);
    if let Some(f) = reply {
        worker_shared(vcpu_id)
            .tx_replies
            .lock()
            .unwrap()
            .push_back(f);
    }
}

// Local copies of the two flag bits this file tests directly; the
// full set lives in `outbound_fsm`.
const SYN_FLAG: u8 = 0x02;
const ACK_FLAG: u8 = 0x10;

/// Open a new outbound flow for a guest SYN: refusal checks, then a
/// non-blocking host `connect(2)`. Returns a reply frame to queue
/// (refusal RST, or SYN-ACK on the rare synchronous connect); the
/// common EINPROGRESS path replies later from the poll side.
fn open_flow(io: &mut IoState, key: OutTcpKey, guest_isn: u32) -> Option<TxFrame> {
    let (guest_port, dst_ip, dst_port) = key;
    let refuse = || {
        let ctl = refuse_syn(guest_isn);
        Some(build_tcp_frame_fixed(
            &GUEST_MAC,
            &IpAddrPair::V4 {
                src: dst_ip,
                dst: VM_IP,
            },
            &TcpFrameSpec {
                src_port: dst_port,
                dst_port: guest_port,
                seq: ctl.seq,
                ack: ctl.ack,
                flags: ctl.flags,
            },
            &[],
        ))
    };

    // Port 0 is never a valid destination; the guest's own address
    // through the proxy is nonsense.
    if dst_port == 0 || dst_ip == VM_IP {
        return refuse();
    }
    // The gateway address maps to host loopback (same NAT the
    // outbound-UDP path applies). On that mapping, refuse the
    // proxy's own TCP listener ports — a guest connect there would
    // loop back into the guest through the inbound forwarder.
    let to_loopback = dst_ip == GW_IP;
    if to_loopback {
        if let Some(listens) = LISTENS.get() {
            if listens.iter().any(|l| l.host_port == dst_port) {
                eprintln!(
                    "[hvf-net] refusing guest outbound TCP to gateway:{dst_port} \
                     (the proxy's own listener port)"
                );
                return refuse();
            }
        }
    }
    if io.outbound_tcp.len() >= MAX_OUTBOUND_TCP {
        eprintln!(
            "[hvf-net] refusing guest outbound TCP to {}.{}.{}.{}:{dst_port}: \
             per-vCPU flow cap ({MAX_OUTBOUND_TCP}) reached",
            dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]
        );
        return refuse();
    }

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return refuse();
    }
    unsafe {
        libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
        let one: i32 = 1;
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &one as *const _ as *const _,
            4,
        );
    }
    let host_ip: [u8; 4] = if to_loopback { [127, 0, 0, 1] } else { dst_ip };
    let addr = libc::sockaddr_in {
        #[cfg(target_os = "macos")]
        sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
        #[cfg(target_os = "macos")]
        sin_family: libc::AF_INET as u8,
        #[cfg(target_os = "linux")]
        sin_family: libc::AF_INET as u16,
        sin_port: dst_port.to_be(),
        sin_addr: libc::in_addr {
            // Network-byte-order memory via from_ne_bytes — same
            // rationale as `handle_udp_outbound`.
            s_addr: u32::from_ne_bytes(host_ip),
        },
        sin_zero: [0; 8],
    };
    let r = unsafe {
        libc::connect(
            fd,
            &addr as *const _ as *const _,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    let mut flow = OutboundTcp {
        fd,
        fsm: OutboundFsm::new(guest_isn, OUT_ISN),
        dst_ip,
        dst_port,
        guest_port,
        pending: Vec::new(),
        host_eof: false,
        last_active: Instant::now(),
    };
    let reply = if r == 0 {
        // Synchronous connect (can happen on loopback) — SYN-ACK now.
        let out = flow.fsm.on_connect_result(true);
        out.ctl.as_ref().map(|c| flow.ctl_frame(c))
    } else {
        let err = unsafe { *libc::__error() };
        if err != libc::EINPROGRESS {
            unsafe {
                libc::close(fd);
            }
            return refuse();
        }
        // Connect in flight — the vCPU poll loop watches POLLOUT and
        // emits the SYN-ACK (or RST) from `drain_outbound_tcp`.
        None
    };
    io.outbound_tcp.insert(key, flow);
    reply
}

/// Inject host→guest payload as ≤`OUT_MAX_PAYLOAD` data segments,
/// advancing `my_seq` per injected chunk. Returns bytes injected —
/// a full RX ring stops early and the caller buffers the rest in
/// `pending` (the FIN, if any, is deferred behind it).
fn inject_outbound_data(
    flow: &mut OutboundTcp,
    data: &[u8],
    qsnap: &virtio::QueueSnapshot,
    rx_last: &mut u16,
    frame_buf: &mut [u8; 2048],
) -> usize {
    let addrs = IpAddrPair::V4 {
        src: flow.dst_ip,
        dst: VM_IP,
    };
    let mut off = 0;
    while off < data.len() {
        let chunk = (data.len() - off).min(OUT_MAX_PAYLOAD);
        let len = write_tcp_frame(
            frame_buf,
            &GUEST_MAC,
            &addrs,
            &TcpFrameSpec {
                src_port: flow.dst_port,
                dst_port: flow.guest_port,
                seq: flow.fsm.my_seq,
                ack: flow.fsm.peer_ack,
                flags: 0x18, // PSH|ACK
            },
            &data[off..off + chunk],
        );
        if !inject_frame(&frame_buf[..len], qsnap, rx_last) {
            break;
        }
        flow.fsm.my_seq = flow.fsm.my_seq.wrapping_add(chunk as u32);
        off += chunk;
    }
    off
}

/// Queue an FSM control verdict toward the guest and apply its
/// host-op/removal. Returns true if a frame was queued.
fn queue_ctl_and_finish(
    io: &mut IoState,
    shared: &WorkerShared,
    key: &OutTcpKey,
    out: SegOut,
) -> bool {
    let mut queued = false;
    if let Some(flow) = io.outbound_tcp.get_mut(key) {
        apply_host_op(flow, &out.host_op);
        if let Some(ctl) = out.ctl.as_ref() {
            shared
                .tx_replies
                .lock()
                .unwrap()
                .push_back(flow.ctl_frame(ctl));
            queued = true;
        }
        if out.remove {
            if let Some(mut f) = io.outbound_tcp.remove(key) {
                close_fd(&mut f.fd, false);
            }
        }
    }
    queued
}

/// Per-iteration outbound-TCP service, run from the vCPU poll loop
/// after `poll(2)`: flush data buffered while the ring was full (and
/// any deferred FIN behind it), resolve connect completions
/// (POLLOUT → SYN-ACK / RST), and pull host→guest data (POLLIN →
/// data segments / FIN on EOF / RST on error).
pub(super) fn drain_outbound_tcp(
    io: &mut IoState,
    shared: &WorkerShared,
    qsnap: &virtio::QueueSnapshot,
    single_queue: bool,
    layout: &PollLayout,
    any_injected: &mut bool,
) {
    if io.outbound_tcp.is_empty() {
        return;
    }
    let mut injected_data = false;
    let mut queued_ctl = false;

    // ── Flush pending host→guest data + deferred FINs ──────────────
    if qsnap.ready
        && io
            .outbound_tcp
            .values()
            .any(|f| !f.pending.is_empty() || f.host_eof)
    {
        let keys: Vec<OutTcpKey> = io
            .outbound_tcp
            .iter()
            .filter(|(_, f)| !f.pending.is_empty() || f.host_eof)
            .map(|(&k, _)| k)
            .collect();
        for key in keys {
            let Some(flow) = io.outbound_tcp.get_mut(&key) else {
                continue;
            };
            if !flow.pending.is_empty() {
                let data = std::mem::take(&mut flow.pending);
                let n = inject_outbound_data(flow, &data, qsnap, &mut io.rx_last, &mut io.frame_buf);
                if n > 0 {
                    injected_data = true;
                }
                if n < data.len() {
                    // Ring filled again — keep the tail (and any
                    // deferred FIN) for the next iteration.
                    flow.pending = data[n..].to_vec();
                    continue;
                }
            }
            if flow.host_eof {
                flow.host_eof = false;
                let out = flow.fsm.on_host_eof();
                queued_ctl |= queue_ctl_and_finish(io, shared, &key, out);
            }
        }
    }

    // ── Poll events on connect-pending / bridging flows ────────────
    for (i, (key, fd, connecting)) in layout.outbound_tcp_drain.iter().enumerate() {
        let revents = io.pollfds[layout.outbound_tcp_slot_start + i].revents;
        if *connecting {
            if revents & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP) == 0 {
                continue;
            }
            // Connect resolved — SO_ERROR tells refused/timeout vs up.
            let mut soerr: i32 = 0;
            let mut slen: libc::socklen_t = std::mem::size_of::<i32>() as u32;
            let r = unsafe {
                libc::getsockopt(
                    *fd,
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    &mut soerr as *mut _ as *mut _,
                    &mut slen,
                )
            };
            let ok = r == 0 && soerr == 0;
            let Some(flow) = io.outbound_tcp.get_mut(key) else {
                continue;
            };
            flow.touch();
            let out = flow.fsm.on_connect_result(ok);
            queued_ctl |= queue_ctl_and_finish(io, shared, key, out);
        } else {
            if revents & (libc::POLLIN | libc::POLLHUP) == 0 {
                continue;
            }
            if let Some(flow) = io.outbound_tcp.get_mut(key) {
                flow.touch();
            }
            queued_ctl |= drain_flow_rx(io, shared, qsnap, key, &mut injected_data);
        }
    }

    if injected_data {
        signal_rx_doorbell(single_queue);
        *any_injected = true;
    }
    if queued_ctl {
        // Same immediate-drain pattern as `accept_listen_backlog` —
        // don't make the SYN-ACK/FIN/RST wait a full poll iteration.
        *any_injected |= drain_tx_replies(io, shared, qsnap, single_queue);
    }
}

/// Drain one bridging flow's host socket: data → guest segments
/// (buffered in `pending` when the ring is unready/full), EOF → FIN
/// (deferred behind pending data), terminal error → RST. Returns
/// true if a control frame was queued.
fn drain_flow_rx(
    io: &mut IoState,
    shared: &WorkerShared,
    qsnap: &virtio::QueueSnapshot,
    key: &OutTcpKey,
    injected_data: &mut bool,
) -> bool {
    let mut buf = [0u8; 4096];
    loop {
        let Some(flow) = io.outbound_tcp.get_mut(key) else {
            return false;
        };
        if flow.fd < 0 {
            return false;
        }
        let n = unsafe { libc::read(flow.fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if n > 0 {
            let n = n as usize;
            if !qsnap.ready || !flow.pending.is_empty() {
                // Ring unavailable (or already behind) — preserve
                // byte order through `pending`.
                flow.pending.extend_from_slice(&buf[..n]);
                continue;
            }
            let injected =
                inject_outbound_data(flow, &buf[..n], qsnap, &mut io.rx_last, &mut io.frame_buf);
            if injected > 0 {
                *injected_data = true;
            }
            if injected < n {
                flow.pending.extend_from_slice(&buf[injected..n]);
            }
            continue;
        }
        if n == 0 {
            // Clean EOF. Close the host fd now (mirrors the inbound
            // path — the kernel socket leaves CLOSE_WAIT instead of
            // leaking); the FIN itself waits behind any pending data.
            close_fd(&mut flow.fd, false);
            if flow.pending.is_empty() {
                let out = flow.fsm.on_host_eof();
                return queue_ctl_and_finish(io, shared, key, out);
            }
            flow.host_eof = true;
            return false;
        }
        let err = unsafe { *libc::__error() };
        if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
            return false;
        }
        // Terminal error (ECONNRESET et al) — reset the guest conn
        // so it frees instead of leaking, same as the inbound path.
        let out = flow.fsm.on_host_error();
        return queue_ctl_and_finish(io, shared, key, out);
    }
}
