//! Per-core QUIC egress scheduler — docs/tx-backpressure.md stage 3, the
//! QUIC arm.
//!
//! A Deficit-Round-Robin fair queue ([`crate::drr`]) becomes the per-core
//! owner of QUIC *ship ordering*. Today every `conn_task` / handler ships
//! its connection's packets inline (`ship_datagram` straight to the NIC),
//! so when N connections each have a response ready in one event-loop pass
//! the order is "whichever task the executor polled first" and one greedy
//! bulk flow can monopolise the TX queue. With the scheduler enabled,
//! connections instead register a *shipper* once and [`activate`] when they
//! have queued outbound packets; a single per-core drain
//! ([`drain_current_core`]) — invoked at the event loop's FLUSH step, after
//! the executor tick — picks a flow by DRR and is the only path that calls
//! `ship_datagram`. Greedy flows get a bounded `quantum` per round; nobody
//! starves.
//!
//! **Switchable, default-OFF.** When disabled (the default) [`register`]
//! returns `None` and every connection keeps the original inline-ship path,
//! byte-for-byte — zero overhead, the scheduler statics are never touched.
//! The app turns it on at boot with [`enable`] (before listeners spawn) and
//! registers [`drain_current_core`] as the event loop's egress-drain hook.
//! Treat the enable flag as boot-time-only; flipping it mid-flight would
//! strand already-activated flows.
//!
//! **Scope.** QUIC builds packets eagerly — the NIC ring slot is acquired
//! at *build* time inside `flush_outbound`, not at ship time — so this arm
//! arbitrates ship *order* over already-acquired packets, not ring
//! *admission*. True just-in-time ring admission (build at drain time, on
//! the freshest cwnd) and the golden-path TCP arm are the documented
//! follow-ups; this is the keystone that wires `net_egress` into the hot
//! path and makes the per-core drain the sole `ship_datagram` caller for
//! QUIC.

use alloc::boxed::Box;
use alloc::rc::{Rc, Weak};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::drr::DeficitRoundRobin;
use waitless::runtime::UdpSocket;
use worker::{CurrentWorker, WorkerLocal};

use crate::endpoint::{ConnArena, ship_datagram};

/// Max concurrent egress-managed QUIC flows per core. A flow id is a dense
/// index assigned from a free list at [`register`] and returned at
/// [`unregister`], decoupled from the sparse (up-to-8192) conn slot so the
/// DRR's fixed-size arrays stay small (~12 KiB/core). If all `N` are in
/// use, a new conn falls back to inline ship (correct, just not scheduled)
/// — 1024 *simultaneously backlogged* QUIC flows on one core is already an
/// extreme operating point.
const N: usize = 1024;

/// DRR send credit (bytes) granted to a flow each time it reaches the head.
/// Sized to several max-size QUIC packets so a lone bulk flow drains a full
/// burst per grant — the drain re-selects the same flow until its
/// `outbound` empties, so single-flow throughput is unthrottled — while N
/// flows still interleave fairly over rounds.
const QUANTUM_BYTES: u32 = 8 * 1500;

/// Backstop on drain iterations per pass. Real flows deactivate when their
/// `outbound` empties; this only guards against a pathological never-empty
/// flow wedging the core.
const MAX_DRAIN_ITERS: u32 = 4096;

/// Everything the drain needs to ship one connection's packets without the
/// owning task: a weak handle to the shared [`ConnArena`] (so a finished
/// conn can't be kept alive by the registry — the arena co-allocates the
/// `Connection` plus the live peer 4-tuple cells, updated by the conn task
/// on migration) and the socket.
struct Shipper {
    conn: Weak<ConnArena>,
    sock: Arc<UdpSocket>,
}

/// Per-core scheduler state. Holds `Rc`/`Weak`/`Cell` (auto-`!Send`); lives
/// in a [`WorkerLocal`] so only the owning core ever constructs, mutates,
/// and drops it — no locks, no cross-core moves.
struct QuicEgress {
    /// Boxed to keep the ~12 KiB of DRR arrays off the construction stack.
    drr: Box<DeficitRoundRobin<N>>,
    /// Shipper per flow id (`None` = free slot).
    ship: Vec<Option<Shipper>>,
    /// Free flow ids (LIFO).
    free: Vec<u16>,
}

// SAFETY: `QuicEgress` only ever moves into / out of its own core's
// `WorkerLocal` slot, and every access goes through `with_mut(&CurrentWorker)`
// on that core. The `Rc`/`Weak` ref counts and `Cell`s inside are therefore
// only ever touched single-threaded by the owning core — never actually sent
// across cores — so asserting `Send` (required for `WorkerLocal<T>: Sync` as
// a static) is sound. Same per-core-exclusivity invariant as `TcpConnCell`
// in net/tcp's pool.
unsafe impl Send for QuicEgress {}

impl QuicEgress {
    fn new() -> Self {
        let mut ship = Vec::with_capacity(N);
        ship.resize_with(N, || None);
        let mut free = Vec::with_capacity(N);
        // Hand out low ids first (nicer locality / debugging).
        for id in (0..N as u16).rev() {
            free.push(id);
        }
        QuicEgress {
            drr: Box::new(DeficitRoundRobin::new()),
            ship,
            free,
        }
    }
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static EGRESS: WorkerLocal<QuicEgress> = WorkerLocal::new();

/// RAII handle tying a flow id's lifetime to its connection's. Both the
/// conn task and the handler [`QuicConn`](crate::endpoint::QuicConn) hold a
/// clone; when the last one drops (i.e. the `Connection` is finished and
/// every sender is gone) `Drop` reclaims the id. This is what keeps id
/// reuse ABA-free: no live holder of a flow id can outlive its reclamation,
/// so a stale [`activate`] is impossible.
pub struct FlowGuard {
    flow: u16,
}

impl FlowGuard {
    /// This connection's dense flow id.
    #[inline]
    pub fn flow(&self) -> u16 {
        self.flow
    }
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        // Runs on the connection's owning core (the conn is core-pinned),
        // and only at task exit — never nested inside another `with_mut`.
        let cc = CurrentWorker::enter();
        EGRESS.with_mut(&cc, |e| {
            if e.ship[self.flow as usize].take().is_some() {
                e.drr.deactivate(self.flow as usize);
                e.free.push(self.flow);
            }
        });
    }
}

/// Turn on per-core egress scheduling and allocate the per-core state.
/// Call once at boot, after `worker::set_num_workers`, before any QUIC
/// listener spawns. The app must also register [`drain_current_core`] as
/// the event loop's egress-drain hook.
pub fn enable() {
    let n = worker::num_workers().max(1);
    EGRESS.ensure_init(n, |_| QuicEgress::new());
    ENABLED.store(true, Ordering::Relaxed);
}

/// Whether egress scheduling is on. Cheap; the inline-ship fast path reads
/// it indirectly via the `Option<u16>` flow id [`register`] hands back.
#[inline]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Register a connection's shipper and return an RAII [`FlowGuard`], or
/// `None` when scheduling is disabled or the per-core table is full (the
/// caller then ships inline). Call once, at connection creation; share the
/// returned guard between the conn task and the handler. The id is
/// reclaimed when the last guard clone drops — never explicitly — so reuse
/// can't race a live sender.
pub(crate) fn register(conn: Weak<ConnArena>, sock: Arc<UdpSocket>) -> Option<Rc<FlowGuard>> {
    if !enabled() {
        return None;
    }
    let cc = CurrentWorker::enter();
    EGRESS.with_mut(&cc, |e| {
        let id = e.free.pop()?;
        e.ship[id as usize] = Some(Shipper { conn, sock });
        Some(Rc::new(FlowGuard { flow: id }))
    })
}

/// Mark a flow ready to ship — it has queued outbound packets. Idempotent
/// (DRR keeps its queue position; new data never jumps the line).
#[inline]
pub fn activate(flow: u16) {
    let cc = CurrentWorker::enter();
    EGRESS.with_mut(&cc, |e| e.drr.activate(flow as usize, QUANTUM_BYTES));
}

/// Drain this core's egress queue: pick flows in DRR order and ship each
/// one's queued packets (up to its granted quantum) until no flow has work
/// or the ring stops accepting. The only `ship_datagram` caller for
/// scheduler-managed connections. Registered by the app as the event
/// loop's egress-drain hook; runs once per pass at the FLUSH step.
pub fn drain_current_core() {
    if !enabled() {
        return;
    }
    let cc = CurrentWorker::enter();
    EGRESS.with_mut(&cc, |e| {
        let mut iters = 0u32;
        while e.drr.has_work() && iters < MAX_DRAIN_ITERS {
            iters += 1;
            let flow = match e.drr.next_flow() {
                Some(f) => f,
                None => break,
            };
            let grant = e.drr.grant(flow);

            // Resolve the shipper. A dead `Weak` means the conn finished
            // before its task's unregister ran (rare; the task holds an
            // `Rc` until exit) — just stop selecting it; unregister will
            // reclaim the id.
            let (arena, sock) = match &e.ship[flow] {
                Some(s) => match s.conn.upgrade() {
                    Some(a) => (a, s.sock.clone()),
                    None => {
                        e.drr.deactivate(flow);
                        continue;
                    }
                },
                None => {
                    e.drr.deactivate(flow);
                    continue;
                }
            };
            let (peer_ip, peer_port) = (arena.peer_ip.get(), arena.peer_port.get());

            // Phase 1 — ship eagerly-built datagrams (handshake / UDP-GSO
            // super-buffers) the conn task queued in `outbound`.
            let mut sent = 0u32;
            loop {
                let pkt = {
                    let mut c = arena.conn.borrow_mut();
                    c.pop_packet_owned()
                };
                let pkt = match pkt {
                    Some(p) => p,
                    None => break,
                };
                let len = pkt.len() as u32;
                ship_datagram(&sock, &arena.conn, peer_ip, peer_port, pkt);
                sent = sent.saturating_add(len);
                if sent >= grant {
                    break;
                }
            }

            // Phase 2 — build-at-drain the steady-state 1-RTT packets: acquire
            // a driver TX slot, encode one packet straight into it, and submit
            // it SYNCHRONOUSLY (zero-copy direct-fill; the synchronous
            // acquire→submit pairing is what makes that aliasing-safe, unlike
            // the eager/`outbound` path). Stops at the DRR grant, the pacer /
            // anti-amp gate, or when nothing more is pending.
            while sent < grant {
                let pkt = {
                    let mut c = arena.conn.borrow_mut();
                    c.build_next_one_rtt_datagram()
                };
                match pkt {
                    Ok(Some(p)) => {
                        let len = p.len() as u32;
                        ship_datagram(&sock, &arena.conn, peer_ip, peer_port, p);
                        sent = sent.saturating_add(len);
                    }
                    Ok(None) | Err(_) => break,
                }
            }
            e.drr.charge(flow, sent);

            // Deactivate when fully drained, OR when nothing shipped this pass
            // (pacing / anti-amp blocked) — the latter avoids re-selecting the
            // flow in a tight spin. Either way the conn task re-activates it on
            // its next wake (inbound datagram or pacing/ACK timer) as long as
            // `has_pending_tx`.
            if sent == 0 || !arena.conn.borrow().has_pending_tx() {
                e.drr.deactivate(flow);
            }
        }
    });
}
