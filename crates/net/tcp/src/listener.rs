// TCP public API surface — handles encode (core, slot) for
// transparent routing. The reactor's TCP backend hooks land here:
// `listen_on_core` / `accept_on_port`, `is_readable_or_closed`,
// `close`, `async_recv` + chunk variants, send-side waker hooks,
// `shutdown_all`. Also `init` (per-core pool / hash bring-up).

use crate::pool::{
    POOLS, TCP_HASH, TcpHashCore, TcpPool, alloc_connection, conn_ptr, decode_handle,
    encode_handle, free_connection, pool_capacity,
};
use crate::send::{SegmentMeta, send_rst};
use crate::state::{TCP_ACK, TCP_FIN, TcpState};
use core::ptr;
use core::task::Waker;
use iobuf::IOBuf;

// `send_segment` is the only `send.rs` helper the close/`Listener`
// paths reach into — used for FIN/ACK control segments. `RecvBufSlot`
// is the typed payload of the direct-copy slot the pub-API setter
// constructs.
use crate::send::send_segment;
use crate::state::RecvBufSlot;

// ============================================================================
// TCP public API — handles encode (core, slot) for transparent routing.
// ============================================================================

/// Initialize TCP connection pools. Each per-core pool starts
/// empty; the first `alloc_connection` call grows it by a segment.
/// No per-core slot pre-init is needed — segment construction
/// initializes every slot to a fresh `TcpConnection` and links them
/// into the free list before publishing the segment.
pub fn init() {
    let n = kernel_core::percpu::num_cores();
    POOLS.init(n, |_| TcpPool::new());
    TCP_HASH.init(n, |_| TcpHashCore::new());
}

/// Create a listener on a specific core. Called from
/// `net::tcp_backend_listen` once per core at `TcpListener::bind`
/// time.
pub fn listen_on_core(core: u32, port: u16) -> *mut () {
    let slot = match alloc_connection(core) {
        Some(i) => i,
        None => return ptr::null_mut(),
    };
    // SAFETY: per-core ownership; only the owning core mutates this slot.
    // listen_on_core is called from app init, single-threaded.
    let c = unsafe { &mut *conn_ptr(core, slot) };
    c.state = TcpState::Listen;
    c.local_port = port;
    encode_handle(core, slot)
}

/// Accept a connection on the **current core** by port — the
/// entry point used by `executor::reactor::TcpListener`'s backend
/// hook. Returns `TcpStream::NULL` if no connection is ready
/// on this core.
pub fn accept_on_port(port: u16) -> executor::reactor::TcpStream {
    accept_on_port_core(kernel_core::cpu_id(), port)
}

fn accept_on_port_core(core: u32, port: u16) -> executor::reactor::TcpStream {
    use executor::reactor::TcpStream;
    let cap = pool_capacity(core);
    for i in 0..cap {
        // SAFETY: per-core ownership.
        let c = unsafe { &mut *conn_ptr(core, i) };
        if c.state == TcpState::Established && c.listener_port == port && !c.accepted {
            c.accepted = true;
            return TcpStream::from_raw(encode_handle(core, i), c.generation);
        }
    }
    TcpStream::NULL
}

/// Async-readiness probe — returns `true` when there's inbound
/// data to consume OR the connection is in a terminal state
/// (Closed / CloseWait / LastAck / TimeWait), so the `TcpRecv`
/// future resolves on peer FIN and the caller sees `recv() == 0`.
/// A `generation` mismatch also reports "ready" so stale handles
/// promptly resolve to closed. Registered as the `TCP_HAS_DATA`
/// hook.
pub fn is_readable_or_closed(handle: *mut (), generation: u16) -> bool {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return true,
    };
    let c = unsafe { &*conn_ptr(core, slot) };
    if c.generation != generation {
        return true; // stale → treat as closed
    }
    // `direct_bytes > 0` covers the case where `deliver_payload`
    // wrote bytes straight into the parked `TcpRecv`'s user buf
    // and bypassed the ring entirely — `rx_used` is 0 in that
    // shape, but the future still has bytes to claim.
    // `pending_chunk` is the `recv_chunk` analogue: a zero-copy
    // IOBuf stashed by `tcp_receive` that `do_recv_chunk` will
    // hand out — also readable with `rx_used == 0`.
    if c.rx_used() > 0 || c.direct_bytes > 0 || c.pending_chunk.is_some() {
        return true;
    }
    matches!(
        c.state,
        TcpState::Closed | TcpState::CloseWait | TcpState::LastAck | TcpState::TimeWait
    )
}

pub fn close(handle: *mut (), generation: u16) {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return,
    };
    // SAFETY: per-core ownership.
    let c = unsafe { &mut *conn_ptr(core, slot) };
    // Stale handle: slot was already reused. Drop on the floor —
    // the slot has its own lifecycle now.
    if c.generation != generation {
        return;
    }
    // Advertise the actual receive-buffer space in the FIN. Sending
    // FIN with `win=0` is technically legal but Linux clients treat
    // it as a zero-window event and queue the FIN+ACK behind a persist
    // timer, leaving the connection orphaned in FIN_WAIT_1 on our side.
    // Since we've drained the request out of the rx ring before
    // responding, `rx_free()` is the full buffer here.
    let win = c.rx_free() as u16;
    match c.state {
        TcpState::Established => {
            send_segment(
                &SegmentMeta {
                    local_ip: c.local_ip,
                    dst_ip: c.remote_ip,
                    src_port: c.local_port,
                    dst_port: c.remote_port,
                    seq: c.snd_nxt,
                    ack: c.rcv_nxt,
                    flags: TCP_FIN | TCP_ACK,
                    window: win,
                },
                &[],
            );
            c.snd_nxt = c.snd_nxt.wrapping_add(1);
            c.state = TcpState::FinWait1;
            // Arm the FIN-retransmit timer: a FIN lost on a lossy WAN
            // is resent by `on_tcp_tick` rather than stranding the
            // connection until the peer's keepalive fires.
            c.arm_fin_timer(kernel_core::clock::now_ms());
        }
        TcpState::CloseWait => {
            send_segment(
                &SegmentMeta {
                    local_ip: c.local_ip,
                    dst_ip: c.remote_ip,
                    src_port: c.local_port,
                    dst_port: c.remote_port,
                    seq: c.snd_nxt,
                    ack: c.rcv_nxt,
                    flags: TCP_FIN | TCP_ACK,
                    window: win,
                },
                &[],
            );
            // The FIN consumes one sequence number. Move to LastAck
            // and wait for the peer to acknowledge it — freeing the
            // slot here (the pre-WAN behaviour) dropped the connection
            // before the ACK and lost the FIN-retransmit guarantee.
            c.snd_nxt = c.snd_nxt.wrapping_add(1);
            c.state = TcpState::LastAck;
            c.arm_fin_timer(kernel_core::clock::now_ms());
        }
        _ => {
            free_connection(core, slot);
        }
    }
}

/// RST every active connection in every core's pool. Called from
/// `waitless::shutdown_and_drop` so the peer sees an immediate close
/// instead of a silently-vanishing VM (which would only time out
/// via TCP keepalive — minutes later). Walks every slot once,
/// emits one RST per non-Closed/Listen conn, frees the slot.
///
/// Safety: by the time this fires, BSP has already broken out of
/// the eventloop and AP cores are spin-looping past their break
/// before they hit PSCI CPU_OFF. They aren't actively mutating
/// their pools, so cross-core read access is race-free for the
/// shutdown window.
pub fn shutdown_all() {
    let n = kernel_core::percpu::num_cores();
    for core in 0..n {
        let cap = pool_capacity(core);
        for slot in 0..cap {
            // SAFETY: see fn-level comment — APs have left the
            // eventloop; only BSP runs this and it owns its own
            // slots, with read-only access to AP slots.
            let c = unsafe { &mut *conn_ptr(core, slot) };
            if c.state != TcpState::Closed && c.state != TcpState::Listen {
                send_rst(
                    c.local_ip,
                    c.remote_ip,
                    c.local_port,
                    c.remote_port,
                    c.snd_nxt,
                    c.rcv_nxt,
                );
                free_connection(core, slot);
            }
            // Release the per-conn RX ring and retransmit ring at
            // shutdown — `free_connection` preserves both across normal
            // close+reuse (the next SYN re-uses the allocations), but at
            // process shutdown there are no more SYNs, and the preserved
            // blocks would show up in `HEAP_LEAK_CHECK` as residual heap
            // the cooldown didn't reclaim. Drop here so the leak-check
            // delta returns to zero.
            // SAFETY: same per-fn invariant as above; the slot is in
            // Closed (post-`free_connection`) or Listen state, neither
            // of which observes the rings.
            let c = unsafe { &mut *conn_ptr(core, slot) };
            c.rx_ring = None;
            c.rtx_buf = None;
        }
    }
    // The caller (`net::bare_shutdown_all`) flushes the NIC TX
    // staging + kick after this returns — this teardown path
    // deliberately leaves that flush to the caller.
}

/// Async `TcpRecv` sync read hook. Verifies `generation`; stale
/// handles return 0 (observed by caller as EOF / close).
pub fn async_recv(handle: *mut (), generation: u16, buf: &mut [u8]) -> usize {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return 0,
    };
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        return 0;
    }
    c.rx_pop(buf)
}

/// Park the current task's waker on this conn, to be woken when
/// data arrives or the peer FINs. Called from
/// `executor::reactor::TcpRecv::poll` on the owning core. A
/// `generation` mismatch fires the waker immediately so the task
/// observes closure on its next poll.
pub fn register_recv_waker(handle: *mut (), generation: u16, waker: &Waker) {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => {
            waker.wake_by_ref();
            return;
        }
    };
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        waker.wake_by_ref();
        return;
    }
    match &c.recv_waker {
        Some(w) if w.will_wake(waker) => {}
        _ => c.recv_waker = Some(waker.clone()),
    }
}

/// Drop the parked waker without firing it. Called from
/// `TcpRecv::poll` after resolving Ready so a subsequent data
/// arrival doesn't wake a no-longer-interested task. Stale
/// `generation` is a no-op.
pub fn clear_recv_waker(handle: *mut (), generation: u16) {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return,
    };
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        return;
    }
    c.recv_waker = None;
}

/// Register the `&mut buf` of a parked `TcpRecv` future as the
/// direct-copy destination for the next inbound TCP payload. Called
/// from `TcpRecv::poll` before parking; `deliver_payload` reads this
/// slot, writes up to `cap` bytes straight into `ptr`, increments
/// `direct_bytes`, and clears the slot.
///
/// Stale `generation` is a no-op — the future will see the closed
/// state via `is_readable_or_closed` and resolve through `do_recv`.
pub fn set_recv_buf_slot(handle: *mut (), generation: u16, ptr: *mut u8, cap: u16) {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return,
    };
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        return;
    }
    c.recv_buf_slot = Some(RecvBufSlot { ptr, cap });
}

/// Drop the registered direct-copy slot. Called from `TcpRecv::Drop`
/// (cancel-safety: future was dropped before waker fired) and from
/// `TcpRecv::poll` after resolving Ready. Stale `generation` is a
/// no-op — the conn slot is already reused for someone else and
/// the new owner's `set_recv_buf_slot` writes will dominate.
pub fn clear_recv_buf_slot(handle: *mut (), generation: u16) {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return,
    };
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        return;
    }
    c.recv_buf_slot = None;
}

/// Register intent to receive the next inbound payload as an owned
/// `IOBuf` (zero copy) rather than copied into a user buffer.
/// Called from `RecvChunk::poll` before parking; `tcp_receive`
/// then moves the next in-sequence single-part segment straight
/// into `pending_chunk` instead of pushing it through `rx_ring`.
///
/// Unlike `set_recv_buf_slot` this carries no pointer — the
/// consumer wants the transport's buffer, not a destination to
/// copy into — so it is just a one-bit "deliver-as-IOBuf" request.
/// Stale `generation` is a no-op; the future resolves to closed
/// via `is_readable_or_closed` + `do_recv_chunk`.
pub fn set_chunk_buf_slot(handle: *mut (), generation: u16) {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return,
    };
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        return;
    }
    c.chunk_wanted = true;
}

/// Drop the chunk-delivery request. Called from `RecvChunk::Drop`
/// (cancel-safety: the future was dropped before resolving) and
/// from `RecvChunk::poll` after resolving Ready. Does NOT discard
/// an already-stashed `pending_chunk` — that IOBuf is still owed to
/// whoever the slot belongs to and is cleared on slot reset. Stale
/// `generation` is a no-op.
pub fn clear_chunk_buf_slot(handle: *mut (), generation: u16) {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return,
    };
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        return;
    }
    c.chunk_wanted = false;
}

/// Async `RecvChunk` consume hook — the `recv_chunk` analogue of
/// `async_recv`. Surfaces the next chunk of inbound data as an
/// owned `IOBuf`:
///
///   * `pending_chunk` — a device buffer `tcp_receive` stashed
///     zero-copy. Returned as-is (an `External` IOBuf): the guard
///     reads it in place and `into_owned()` keeps it zero-copy.
///   * otherwise, if `rx_ring` holds bytes, they are drained into
///     a fresh `Heap` IOBuf. `pending_chunk` is only ever stashed
///     while the ring is empty, so draining it first then the ring
///     preserves stream order.
///   * `None` — no data: EOF / peer close / stale `generation`,
///     observed by the caller as the end of the body.
pub fn do_recv_chunk(handle: *mut (), generation: u16) -> Option<IOBuf> {
    let (core, slot) = decode_handle(handle)?;
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        return None;
    }
    if let Some(iobuf) = c.pending_chunk.take() {
        // Zero-copy stash: the device RX buffer is surfaced as-is.
        crate::diag::COUNTERS.rx_chunk_stash_hits.bump();
        return Some(iobuf);
    }
    let n = c.rx_used();
    if n == 0 {
        return None;
    }
    // Drain the ring into an owned heap buffer. `rx_pop` also runs
    // the SWS window-update check, so a chunk read reopens the
    // receive window exactly as a `recv` read does.
    let mut v = alloc::vec::Vec::new();
    if v.try_reserve_exact(n).is_err() {
        return None;
    }
    v.resize(n, 0);
    let got = c.rx_pop(&mut v);
    v.truncate(got);
    // Ring-drain fallback: one memcpy (rx_ring → Heap IOBuf). Not
    // zero-copy — `into_owned()` on this is free, but the bytes
    // already moved through the ring.
    crate::diag::COUNTERS.rx_chunk_ring_drain.bump();
    Some(IOBuf::from(v))
}

/// Park the send-side waker. On bare-metal `async_try_send_chain`
/// always accepts the whole buffer, so this path is effectively
/// unreachable during steady-state sends; kept symmetric with the
/// recv side so future NIC-TX-backpressure plumbing (or a proper
/// TCP send-window) can light it up without API churn. Stale
/// `generation` wakes the waker immediately so the task observes
/// closure.
pub fn register_send_waker(handle: *mut (), generation: u16, waker: &Waker) {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => {
            waker.wake_by_ref();
            return;
        }
    };
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        waker.wake_by_ref();
        return;
    }
    // Write-readiness on bare-metal: the NIC TX path is always
    // "ready" for this stack. Fire immediately so the future
    // re-probes and resolves.
    waker.wake_by_ref();
}

pub fn clear_send_waker(_handle: *mut (), _generation: u16) {
    // No-op on bare-metal — no send-waker state to clear.
}

