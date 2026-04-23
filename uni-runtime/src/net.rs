// uni-runtime/src/net.rs — UDP reactor.
//
// `UdpSocket::bind(port)` claims one of `MAX_UDP_SOCKETS` static slots.
// The socket owns a SPSC ring buffer of fixed-size datagram slots and
// a single waker cell. The awaiting task's waker is stored there when
// `UdpRecv` polls Pending; the network backend (bare-metal NIC
// interrupt path on the unikernel, kqueue/epoll loop on native) calls
// `deliver_udp(port, src_ip, src_port, payload)` once per inbound
// datagram, which pushes the payload into the inbox and wakes the
// task.
//
// Cancellation-safety: `poll` does the fast-path pop BEFORE registering
// a waker, and re-checks the inbox AFTER register — closes the
// delivery-vs-registration race in both directions without ever
// popping a datagram speculatively. Dropping `UdpRecv` mid-await
// doesn't consume any datagram — they stay in the inbox for the next
// `recv_from` call.

use core::cell::{Cell, UnsafeCell};
use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use core::task::{Context, Poll, Waker};

// ---- Sizing -----------------------------------------------------------------

/// Maximum concurrently-bound UDP sockets across the whole binary.
/// 8 fits today's use (DHCP, QUIC, one or two app-level endpoints) and
/// keeps the static backing footprint bounded.
pub const MAX_UDP_SOCKETS: usize = 8;

/// Inbox ring capacity per socket. Must be a power of two for the
/// wrap-around math.
const INBOX_CAPACITY: usize = 8;

/// Max payload bytes per datagram. Ethernet MTU minus headers; we
/// copy into fixed-size slots so the inbox has no heap dependency.
const MAX_PAYLOAD: usize = 1500;

// ---- SpinLock ---------------------------------------------------------------
//
// Self-contained, CAS-based lock for the per-socket waker slot. The
// waker is the only shared mutable state that can't be represented as
// a plain atomic (it's a fat pointer + vtable), and the spinlock
// region is tiny (clone / take). Wrote this here rather than depend
// on `uni_kernel::sync::Spinlock` because `uni-runtime` must not
// depend on `//kernel`.

struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: `SpinLock` only hands out guarded access to the contained
// `T` one caller at a time, so a cross-thread `&SpinLock<T>` is sound
// as long as `T: Send` (the lock transfers ownership of `&mut T`
// across threads).
unsafe impl<T: Send> Sync for SpinLock<T> {}

struct SpinGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> SpinLock<T> {
    const fn new(v: T) -> Self {
        SpinLock {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(v),
        }
    }

    fn lock(&self) -> SpinGuard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        SpinGuard { lock: self }
    }
}

impl<'a, T> core::ops::Deref for SpinGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: holding the lock gives us exclusive access.
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> core::ops::DerefMut for SpinGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: holding the lock gives us exclusive access.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for SpinGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

// ---- Datagram inbox ---------------------------------------------------------

#[repr(C)]
struct Datagram {
    src_ip: [u8; 4],
    src_port: u16,
    len: u16,
    payload: [u8; MAX_PAYLOAD],
}

impl Datagram {
    const ZERO: Self = Datagram {
        src_ip: [0; 4],
        src_port: 0,
        len: 0,
        payload: [0; MAX_PAYLOAD],
    };
}

struct Inbox {
    /// Port this inbox is bound to. `0` = slot free.
    port: AtomicU16,
    /// Consumer cursor (read by `pop_into`, incremented after a pop).
    head: AtomicU32,
    /// Producer cursor (read by `try_push`, incremented after a push).
    tail: AtomicU32,
    /// Fixed-size ring of datagram slots. Producer owns `[tail..)`,
    /// consumer owns `[head..tail)`.
    slots: UnsafeCell<[Datagram; INBOX_CAPACITY]>,
    /// Waker registered by the awaiting task, fired by `deliver_udp`.
    waker: SpinLock<Option<Waker>>,
}

// SAFETY: slots is SPSC-disciplined via head/tail cursors (one
// producer, one consumer); waker is SpinLock-guarded; port is atomic.
unsafe impl Sync for Inbox {}

impl Inbox {
    const fn new() -> Self {
        Inbox {
            port: AtomicU16::new(0),
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            slots: UnsafeCell::new([const { Datagram::ZERO }; INBOX_CAPACITY]),
            waker: SpinLock::new(None),
        }
    }

    /// Producer-side. Returns `true` iff the datagram was accepted.
    /// Full inbox drops the datagram — same semantics as OS socket
    /// buffer overrun.
    fn try_push(&self, src_ip: [u8; 4], src_port: u16, payload: &[u8]) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        let next = tail.wrapping_add(1) % INBOX_CAPACITY as u32;
        if next == head {
            return false;
        }
        // SAFETY: SPSC — the tail slot is owned by the producer until
        // we Release the updated tail below.
        let slots = unsafe { &mut *self.slots.get() };
        let slot = &mut slots[tail as usize];
        slot.src_ip = src_ip;
        slot.src_port = src_port;
        let n = payload.len().min(MAX_PAYLOAD);
        slot.len = n as u16;
        slot.payload[..n].copy_from_slice(&payload[..n]);
        self.tail.store(next, Ordering::Release);
        true
    }

    /// Consumer-side. Copies one datagram into `buf`; returns
    /// `(src_ip, src_port, bytes_written)` or `None` if empty.
    fn pop_into(&self, buf: &mut [u8]) -> Option<([u8; 4], u16, usize)> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        // SAFETY: SPSC — the head slot is owned by the consumer until
        // we Release the updated head below.
        let slots = unsafe { &*self.slots.get() };
        let slot = &slots[head as usize];
        let n = (slot.len as usize).min(buf.len());
        buf[..n].copy_from_slice(&slot.payload[..n]);
        let r = (slot.src_ip, slot.src_port, n);
        let next = head.wrapping_add(1) % INBOX_CAPACITY as u32;
        self.head.store(next, Ordering::Release);
        Some(r)
    }
}

// ---- Registry ---------------------------------------------------------------

static REGISTRY: [Inbox; MAX_UDP_SOCKETS] = [const { Inbox::new() }; MAX_UDP_SOCKETS];

// ---- Public API -------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpBindError {
    /// No free socket slot (all `MAX_UDP_SOCKETS` in use).
    AllSlotsBusy,
    /// Another `UdpSocket` is already bound to this port.
    PortInUse,
    /// `port == 0` — not a valid bind target.
    InvalidPort,
}

/// A UDP socket bound to one port. Dropping releases the slot.
/// Not `Clone` / not `Sync`: the associated inbox has a single
/// waker cell, so two concurrent `recv_from` callers would clobber
/// each other's waker. One task per socket. The `PhantomData<Cell<()>>`
/// carries the `!Sync` auto-trait opt-out without touching the
/// unstable `negative_impls` feature.
pub struct UdpSocket {
    port: u16,
    idx: usize,
    _not_sync: PhantomData<Cell<()>>,
}

impl UdpSocket {
    pub fn bind(port: u16) -> Result<UdpSocket, UdpBindError> {
        if port == 0 {
            return Err(UdpBindError::InvalidPort);
        }
        // First scan for a duplicate bind.
        for inbox in REGISTRY.iter() {
            if inbox.port.load(Ordering::Acquire) == port {
                return Err(UdpBindError::PortInUse);
            }
        }
        // Then claim a free slot via CAS on `port` (0 → port).
        for (idx, inbox) in REGISTRY.iter().enumerate() {
            if inbox
                .port
                .compare_exchange(0, port, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // Reset per-slot state in case this slot was used
                // before and released. SPSC cursors only need to be
                // consistent with each other; any stale datagram
                // bytes are overwritten before the next `pop_into`
                // reads them (producer writes len + payload first,
                // consumer reads them after).
                inbox.head.store(0, Ordering::Relaxed);
                inbox.tail.store(0, Ordering::Relaxed);
                *inbox.waker.lock() = None;
                return Ok(UdpSocket {
                    port,
                    idx,
                    _not_sync: PhantomData,
                });
            }
        }
        Err(UdpBindError::AllSlotsBusy)
    }

    /// Port this socket is bound to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Await one datagram on this socket. The copy into `buf`
    /// happens on the single poll that returns `Ready`. Returns
    /// `(src_ip, src_port, bytes_written)`. Truncates oversized
    /// payloads to `buf.len()`.
    pub fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> UdpRecv<'a> {
        UdpRecv { sock: self, buf }
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        let inbox = &REGISTRY[self.idx];
        // Clear the waker first so any in-flight `deliver_udp` for
        // this slot can't wake a stale task after we release the
        // port. Order: waker → port, mirroring the order a new
        // `bind` observes them in its pre-claim scan.
        *inbox.waker.lock() = None;
        inbox.port.store(0, Ordering::Release);
    }
}

pub struct UdpRecv<'a> {
    sock: &'a UdpSocket,
    buf: &'a mut [u8],
}

impl<'a> Future for UdpRecv<'a> {
    type Output = ([u8; 4], u16, usize);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let inbox = &REGISTRY[this.sock.idx];

        // Fast path: data already in the inbox. Avoids the waker
        // clone / spinlock in the common case.
        if let Some(r) = inbox.pop_into(this.buf) {
            return Poll::Ready(r);
        }

        // Slow path: register the waker, then re-check. The re-check
        // closes the race where `deliver_udp` pushed a datagram
        // between the fast-path pop_into and the waker registration
        // — without it, the task would sleep despite data sitting in
        // the inbox.
        *inbox.waker.lock() = Some(cx.waker().clone());
        if let Some(r) = inbox.pop_into(this.buf) {
            // Completing now, clear the waker so we don't get an
            // unnecessary wake later.
            *inbox.waker.lock() = None;
            return Poll::Ready(r);
        }

        Poll::Pending
    }
}

// ---- Backend entry point ----------------------------------------------------

/// Deliver one inbound UDP datagram to whichever `UdpSocket` is
/// bound to `dst_port`. Called from the network RX path — bare-metal
/// `net::udp::udp_receive` on the unikernel, `drain_udp_sibling` on
/// native. Returns `true` if a socket was found (accepting or
/// dropping the datagram), `false` otherwise.
///
/// A full inbox drops the datagram but still fires the waker — any
/// pending `UdpRecv` gets a chance to drain what's already there.
pub fn deliver_udp(dst_port: u16, src_ip: [u8; 4], src_port: u16, payload: &[u8]) -> bool {
    for inbox in REGISTRY.iter() {
        if inbox.port.load(Ordering::Acquire) == dst_port {
            let _ = inbox.try_push(src_ip, src_port, payload);
            // Fire the waker (if registered) regardless of push
            // success — a full inbox means the task needs to drain;
            // waking it lets it catch up.
            let taken = inbox.waker.lock().take();
            if let Some(waker) = taken {
                waker.wake();
            }
            return true;
        }
    }
    false
}
