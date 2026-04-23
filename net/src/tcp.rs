// net/tcp.rs — TCP state machine, per-core connection pool, ring buffers.
//
// Connections are partitioned across cores. Each core owns a slice of
// the global pool. The flow hash (in net/lib.rs) routes packets to the
// owning core. All connection operations are core-local — no locks.

#![no_std]

extern crate alloc;
extern crate uni_kernel;
extern crate uni_runtime;
extern crate net_from_bytes as from_bytes;
extern crate net_types as types;
extern crate net_ipv4 as ipv4;
extern crate bitflags;

use alloc::alloc::{alloc_zeroed, Layout};
use alloc::boxed::Box;
use core::ptr;
use core::task::Waker;
use from_bytes::FromBytes;
use types::{Ipv4Addr, CONFIG, tcp_checksum, htons, ntohs, htonl, ntohl};
use ipv4::{ipv4_send, PROTO_TCP};

/// Heap-allocate a zero-filled `Box<[u8]>` of `len` bytes, returning
/// `None` on OOM instead of aborting. `vec![0u8; len].into_boxed_slice()`
/// would panic on failure; we refuse the connection instead.
fn try_zeroed_boxed_slice(len: usize) -> Option<Box<[u8]>> {
    if len == 0 {
        return None;
    }
    let layout = Layout::from_size_align(len, 1).ok()?;
    // SAFETY: non-zero size, u8 has no invalid bit patterns so
    // zero-initialised memory is a valid `[u8]`; Box::from_raw
    // takes ownership of the freshly-allocated slice pointer.
    unsafe {
        let raw = alloc_zeroed(layout);
        if raw.is_null() {
            return None;
        }
        let slice = core::slice::from_raw_parts_mut(raw, len);
        Some(Box::from_raw(slice))
    }
}

bitflags::bitflags! {
    struct TcpFlags: u8 {
        const FIN = 0x01;
        const SYN = 0x02;
        const RST = 0x04;
        const PSH = 0x08;
        const ACK = 0x10;
    }
}

const TCP_FIN: u8 = TcpFlags::FIN.bits();
const TCP_SYN: u8 = TcpFlags::SYN.bits();
const TCP_RST: u8 = TcpFlags::RST.bits();
const TCP_PSH: u8 = TcpFlags::PSH.bits();
const TCP_ACK: u8 = TcpFlags::ACK.bits();

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpState {
    Closed = 0,
    Listen,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    TimeWait,
}

#[repr(C, packed)]
struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    data_offset: u8,
    flags: u8,
    window: u16,
    checksum: u16,
    urgent: u16,
}

// SAFETY: repr(C, packed), all fields are POD integers.
unsafe impl FromBytes for TcpHeader {}

const CONNECTIONS_PER_CORE: usize = 128;
const MAX_CORES: usize = 8;
const RX_BUF_SIZE: usize = 8192;
const MSS: usize = 1460;

pub struct TcpConnection {
    pub state: TcpState,
    remote_ip: Ipv4Addr,
    local_port: u16,
    remote_port: u16,
    snd_nxt: u32,
    snd_una: u32,
    rcv_nxt: u32,
    rcv_wnd: u16,
    /// Owned RX ring buffer. `None` until the connection is accepted
    /// (allocated in `tcp_receive` SYN handling), then a `Box<[u8]>`
    /// of length `RX_BUF_SIZE`. Drop returns the bytes to the global
    /// allocator automatically when the connection is reset.
    rx_buf: Option<Box<[u8]>>,
    rx_head: usize,
    rx_tail: usize,
    listener_port: u16,
    accepted: bool,
    /// Parked `TcpRecvReady` waker. Set by
    /// `tcp_register_recv_waker` on the owning core; woken when data
    /// lands in `rx_buf` or the peer closes. Per-core ownership — no
    /// lock needed.
    recv_waker: Option<Waker>,
}

impl TcpConnection {
    const fn new() -> Self {
        TcpConnection {
            state: TcpState::Closed,
            remote_ip: Ipv4Addr::ANY,
            local_port: 0,
            remote_port: 0,
            snd_nxt: 0,
            snd_una: 0,
            rcv_nxt: 0,
            rcv_wnd: RX_BUF_SIZE as u16,
            rx_buf: None,
            rx_head: 0,
            rx_tail: 0,
            listener_port: 0,
            accepted: false,
            recv_waker: None,
        }
    }

    #[inline]
    fn rx_buf_size(&self) -> usize {
        self.rx_buf.as_ref().map(|b| b.len()).unwrap_or(0)
    }

    fn rx_used(&self) -> usize {
        let size = self.rx_buf_size();
        if size == 0 { return 0; }
        if self.rx_head >= self.rx_tail {
            self.rx_head - self.rx_tail
        } else {
            size - self.rx_tail + self.rx_head
        }
    }

    fn rx_free(&self) -> usize {
        let size = self.rx_buf_size();
        if size == 0 { return 0; }
        size - 1 - self.rx_used()
    }

    fn rx_push(&mut self, data: &[u8]) -> usize {
        let size = self.rx_buf_size();
        if size == 0 { return 0; }
        let free = self.rx_free();
        let n = data.len().min(free);
        if n == 0 { return 0; }
        let contig = size - self.rx_head;
        let buf = self.rx_buf.as_mut().unwrap();
        if n <= contig {
            buf[self.rx_head..self.rx_head + n].copy_from_slice(&data[..n]);
        } else {
            buf[self.rx_head..self.rx_head + contig].copy_from_slice(&data[..contig]);
            buf[..n - contig].copy_from_slice(&data[contig..n]);
        }
        self.rx_head = (self.rx_head + n) % size;
        n
    }

    fn rx_pop(&mut self, out: &mut [u8]) -> usize {
        let size = self.rx_buf_size();
        if size == 0 { return 0; }
        let used = self.rx_used();
        let n = out.len().min(used);
        if n == 0 { return 0; }
        let contig = size - self.rx_tail;
        let buf = self.rx_buf.as_ref().unwrap();
        if n <= contig {
            out[..n].copy_from_slice(&buf[self.rx_tail..self.rx_tail + n]);
        } else {
            out[..contig].copy_from_slice(&buf[self.rx_tail..self.rx_tail + contig]);
            out[contig..n].copy_from_slice(&buf[..n - contig]);
        }
        self.rx_tail = (self.rx_tail + n) % size;
        n
    }
}

// Per-core connection pools. Core N owns POOLS[N].
//
// Each `TcpConnection` is wrapped in `TcpConnCell` (an `UnsafeCell`
// newtype) so cores share the `POOLS` static via shared references
// rather than aliased `&mut`. The outer per-core array is held in
// `uni_kernel::percpu::PerCpu`, which provides typed `current(&CurrentCore)`
// access without manual unsafe at the call site.
//
// SAFETY discipline (enforced by flow-hash routing in net/lib.rs and by
// the API's `cpu_id()` calls): the connection at `POOLS[core][slot]` is
// only mutated by code running on the matching core. The handles
// returned by `encode_handle` carry the core id, and every public TCP
// API decodes the handle and only ever accesses the matching core's
// slots. Tier 2 RX is delivered to the owning core via `rx_inbox` before
// `tcp_receive` runs, so cross-core access cannot occur there either.
struct TcpConnCell(core::cell::UnsafeCell<TcpConnection>);
// SAFETY: per-core ownership documented above; each core only mutates
// its own slots, no two threads ever hold &mut to the same TcpConnection.
unsafe impl Sync for TcpConnCell {}
unsafe impl Send for TcpConnCell {}
impl TcpConnCell {
    const fn new() -> Self {
        TcpConnCell(core::cell::UnsafeCell::new(TcpConnection::new()))
    }
}

type CoreSlots = [TcpConnCell; CONNECTIONS_PER_CORE];

static POOLS: uni_kernel::percpu::PerCpu<CoreSlots, MAX_CORES> =
    uni_kernel::percpu::PerCpu::new(
        [const { [const { TcpConnCell::new() }; CONNECTIONS_PER_CORE] }; MAX_CORES],
    );

// ---- Per-core 4-tuple → slot hash table ------------------------------------
//
// The hot RX path needs to map (src_ip, src_port, dst_port) to the
// TcpConnection slot hosting that flow. A linear scan over
// `CONNECTIONS_PER_CORE` slots per packet was costing ~10 % of a
// core at 113 k rps with 32 live conns. An open-addressed hash table
// with a simple Fibonacci hash lookup is effectively O(1).
//
// Per-core, single-writer discipline. All state lives in the
// `TcpHashCore::keys` + `slots` pair, protected by the same
// "only the owning core touches its slot" contract as `POOLS`.
//
// Key packing: `(ip << 32) | (rport << 16) | lport | (1 << 63)`.
// The top-bit flag makes "key == 0" the unambiguous empty marker.
const TCP_HASH_SIZE: usize = 256;
const TCP_HASH_MASK: usize = TCP_HASH_SIZE - 1;

struct TcpHashCore {
    keys: core::cell::UnsafeCell<[u64; TCP_HASH_SIZE]>,
    slots: core::cell::UnsafeCell<[u16; TCP_HASH_SIZE]>,
}
unsafe impl Sync for TcpHashCore {}
unsafe impl Send for TcpHashCore {}
impl TcpHashCore {
    const fn new() -> Self {
        TcpHashCore {
            keys: core::cell::UnsafeCell::new([0; TCP_HASH_SIZE]),
            slots: core::cell::UnsafeCell::new([0; TCP_HASH_SIZE]),
        }
    }
}

static TCP_HASH: uni_kernel::percpu::PerCpu<TcpHashCore, MAX_CORES> =
    uni_kernel::percpu::PerCpu::new(
        [const { TcpHashCore::new() }; MAX_CORES],
    );

#[inline]
fn tcp_hash_key(src_ip: Ipv4Addr, src_port: u16, dst_port: u16) -> u64 {
    let ip = u32::from_be_bytes(src_ip.octets()) as u64;
    (ip << 32) | ((src_port as u64) << 16) | (dst_port as u64) | (1u64 << 63)
}

#[inline]
fn tcp_hash_bucket(key: u64) -> usize {
    // Fibonacci hash — multiplies by 2^64/phi and takes the top
    // bits. Fast (one imul), good distribution for arbitrary
    // 64-bit keys.
    let h = key.wrapping_mul(0x9E3779B97F4A7C15);
    (h >> (64 - 8)) as usize
}

fn tcp_hash_find(core: u32, key: u64) -> Option<usize> {
    let h = TCP_HASH.at(core);
    // SAFETY: per-core ownership, only the owning core reads/writes.
    let keys = unsafe { &*h.keys.get() };
    let slots = unsafe { &*h.slots.get() };
    let start = tcp_hash_bucket(key);
    for i in 0..TCP_HASH_SIZE {
        let idx = (start + i) & TCP_HASH_MASK;
        let k = keys[idx];
        if k == 0 { return None; }
        if k == key { return Some(slots[idx] as usize); }
    }
    None
}

fn tcp_hash_insert(core: u32, key: u64, slot: usize) {
    let h = TCP_HASH.at(core);
    let keys = unsafe { &mut *h.keys.get() };
    let slots = unsafe { &mut *h.slots.get() };
    let start = tcp_hash_bucket(key);
    for i in 0..TCP_HASH_SIZE {
        let idx = (start + i) & TCP_HASH_MASK;
        if keys[idx] == 0 || keys[idx] == key {
            keys[idx] = key;
            slots[idx] = slot as u16;
            return;
        }
    }
    // Table full — CONNECTIONS_PER_CORE=128 < TCP_HASH_SIZE=256,
    // so this path is effectively unreachable under normal load.
}

fn tcp_hash_remove(core: u32, key: u64) {
    let h = TCP_HASH.at(core);
    let keys = unsafe { &mut *h.keys.get() };
    let slots = unsafe { &mut *h.slots.get() };
    let start = tcp_hash_bucket(key);
    // First find the entry.
    let mut found_idx = None;
    for i in 0..TCP_HASH_SIZE {
        let idx = (start + i) & TCP_HASH_MASK;
        let k = keys[idx];
        if k == 0 { return; }
        if k == key { found_idx = Some(idx); break; }
    }
    let idx = match found_idx {
        Some(i) => i,
        None => return,
    };
    keys[idx] = 0;
    slots[idx] = 0;
    // Back-shift the open-addressing run so later probes for keys
    // that collided past this slot still find them. Stop at the
    // first empty slot.
    let mut i = (idx + 1) & TCP_HASH_MASK;
    while keys[i] != 0 {
        let moving_key = keys[i];
        let moving_slot = slots[i];
        keys[i] = 0;
        slots[i] = 0;
        // Re-insert the displaced entry from its ideal bucket.
        let mut new_idx = tcp_hash_bucket(moving_key);
        while keys[new_idx] != 0 {
            new_idx = (new_idx + 1) & TCP_HASH_MASK;
        }
        keys[new_idx] = moving_key;
        slots[new_idx] = moving_slot;
        i = (i + 1) & TCP_HASH_MASK;
    }
}

/// Get a `*mut TcpConnection` for `(core, slot)`. The caller must
/// uphold the per-core ownership discipline (only the owning core may
/// dereference the resulting pointer mutably).
#[inline]
fn conn_ptr(core: u32, slot: usize) -> *mut TcpConnection {
    POOLS.at(core)[slot].0.get()
}

/// Draw a per-connection initial sequence number.
///
/// Previously this was a global counter that stepped by 64 000, which
/// made the ISN trivially guessable and invited off-path sequence
/// injection. Each new connection now gets a fresh 32-bit sample from
/// the kernel RNG (ChaCha20 keystream, seeded from jitter + RDRAND on
/// x86). One ChaCha block / connection is well below SYN cost.
#[inline]
fn next_seq() -> u32 {
    let mut buf = [0u8; 4];
    uni_kernel::rng::fill_bytes(&mut buf);
    u32::from_ne_bytes(buf)
}

/// Encode a connection handle from core + slot index.
/// Handle = (core << 8) | slot, +1 to avoid null.
fn encode_handle(core: u32, slot: usize) -> *mut () {
    (((core as usize) << 8 | slot) + 1) as *mut ()
}

/// Decode a handle into (core, slot).
fn decode_handle(handle: *mut ()) -> Option<(u32, usize)> {
    let v = (handle as usize).wrapping_sub(1);
    let core = (v >> 8) as u32;
    let slot = v & 0xFF;
    if core as usize >= MAX_CORES || slot >= CONNECTIONS_PER_CORE {
        None
    } else {
        Some((core, slot))
    }
}

fn alloc_connection(core: u32) -> Option<usize> {
    for i in 0..CONNECTIONS_PER_CORE {
        // SAFETY: per-core ownership; only the owning core (which is `core`
        // by the public API contract) calls this.
        let c = unsafe { &mut *conn_ptr(core, i) };
        if c.state == TcpState::Closed {
            *c = TcpConnection::new();
            return Some(i);
        }
    }
    None
}

fn free_connection(core: u32, slot: usize) {
    // SAFETY: per-core ownership.
    let c = unsafe { &mut *conn_ptr(core, slot) };
    // Remove this connection's 4-tuple from the per-core hash index
    // so future packets won't hit a stale entry. No-op for listeners
    // (they aren't inserted).
    if c.state != TcpState::Closed && c.state != TcpState::Listen {
        let key = tcp_hash_key(c.remote_ip, c.remote_port, c.local_port);
        tcp_hash_remove(core, key);
    }
    // Fire any parked `TcpRecvReady` waker before the slot is reset
    // — the app handler needs to observe teardown (is_closed → true)
    // rather than sleeping on a stale waker that would get dropped.
    if let Some(w) = c.recv_waker.take() {
        w.wake();
    }
    // Assigning a fresh TcpConnection drops the old one, which runs
    // the Drop impl on `rx_buf: Option<Box<[u8]>>` — Box::drop returns
    // the bytes to the global allocator. No manual kfree needed.
    *c = TcpConnection::new();
}

fn send_segment(
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) {
    let payload_len = payload.len().min(MSS);
    let seg_len = 20 + payload_len;

    let mut buf = core::mem::MaybeUninit::<[u8; 20 + MSS]>::uninit();
    let p = buf.as_mut_ptr() as *mut u8;

    unsafe {
        let hdr = &mut *(p as *mut TcpHeader);
        hdr.src_port = htons(src_port);
        hdr.dst_port = htons(dst_port);
        hdr.seq = htonl(seq);
        hdr.ack = htonl(ack);
        hdr.data_offset = 0x50;
        hdr.flags = flags;
        hdr.window = htons(window);
        hdr.checksum = 0;
        hdr.urgent = 0;

        if !payload.is_empty() {
            ptr::copy_nonoverlapping(payload.as_ptr(), p.add(20), payload_len);
        }

        hdr.checksum = tcp_checksum(CONFIG.ip(), dst_ip, PROTO_TCP, p, seg_len);

        ipv4_send(dst_ip, PROTO_TCP, core::slice::from_raw_parts(p, seg_len));
    }
}

fn send_rst(dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, seq: u32, ack: u32) {
    let mut buf = core::mem::MaybeUninit::<[u8; 20]>::uninit();
    let p = buf.as_mut_ptr() as *mut u8;
    unsafe {
        let hdr = &mut *(p as *mut TcpHeader);
        hdr.src_port = htons(src_port);
        hdr.dst_port = htons(dst_port);
        hdr.seq = htonl(seq);
        hdr.ack = htonl(ack);
        hdr.data_offset = 0x50;
        hdr.flags = TCP_RST | TCP_ACK;
        hdr.window = 0;
        hdr.checksum = 0;
        hdr.urgent = 0;

        hdr.checksum = tcp_checksum(CONFIG.ip(), dst_ip, PROTO_TCP, p, 20);

        ipv4_send(dst_ip, PROTO_TCP, core::slice::from_raw_parts(p, 20));
    }
}

/// Process an incoming TCP packet. Called on the owning core (via flow hash).
pub fn tcp_receive(src_ip: Ipv4Addr, _dst_ip: Ipv4Addr, data: &[u8]) {
    let hdr = match TcpHeader::try_ref_from(data) {
        Some(h) => h,
        None => return,
    };
    let src_port = ntohs(hdr.src_port);
    let dst_port = ntohs(hdr.dst_port);
    let seq = ntohl(hdr.seq);
    let ack = ntohl(hdr.ack);
    let flags = hdr.flags;
    let data_offset = ((hdr.data_offset >> 4) as usize) * 4;
    let payload_len = if data.len() > data_offset { data.len() - data_offset } else { 0 };
    let payload = &data[data_offset..];

    // Determine which core owns this packet.
    let core = uni_kernel::cpu_id();

    // SAFETY for the closures below: per-core ownership — only this
    // core (== `core`) is touching POOLS[core][*].

    // RST handling.
    //
    // RFC 5961 §3.2: a blind off-path attacker with knowledge of the
    // 4-tuple could otherwise send `RST, seq=<anything>` to tear the
    // connection down. Only accept the reset if seq == rcv_nxt (the
    // strict in-sequence position). Any other seq is silently dropped.
    if flags & TCP_RST != 0 {
        for i in 0..CONNECTIONS_PER_CORE {
            let c = unsafe { &*conn_ptr(core, i) };
            if c.state != TcpState::Closed
                && c.state != TcpState::Listen
                && c.remote_ip == src_ip
                && c.local_port == dst_port
                && c.remote_port == src_port
            {
                if seq == c.rcv_nxt {
                    free_connection(core, i);
                }
                return;
            }
        }
        return;
    }

    // SYN — new connection from client
    if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 {
        // Find listener on this core
        let listener_idx = {
            let mut found = None;
            for i in 0..CONNECTIONS_PER_CORE {
                let c = unsafe { &*conn_ptr(core, i) };
                if c.state == TcpState::Listen && c.local_port == dst_port {
                    found = Some(i);
                    break;
                }
            }
            found
        };

        if listener_idx.is_none() {
            send_rst(src_ip, dst_port, src_port, 0, seq + 1);
            return;
        }

        // Allocate new connection on this core
        let slot = match alloc_connection(core) {
            Some(i) => i,
            None => return,
        };

        {
            let c = unsafe { &mut *conn_ptr(core, slot) };
            c.state = TcpState::SynReceived;
            c.remote_ip = src_ip;
            c.local_port = dst_port;
            c.remote_port = src_port;
            let isn = next_seq();
            c.snd_nxt = isn;
            c.snd_una = c.snd_nxt;
            c.rcv_nxt = seq + 1;
            c.listener_port = dst_port;
            c.accepted = false;

            // Allocate RX buffer. Box drops back to the global
            // allocator automatically when the connection is reset;
            // `try_zeroed_boxed_slice` returns None on OOM so we
            // refuse the connection instead of aborting.
            c.rx_buf = try_zeroed_boxed_slice(RX_BUF_SIZE);
            c.rx_head = 0;
            c.rx_tail = 0;
        }

        // Publish this 4-tuple to the per-core hash index so the
        // subsequent ACK + data segments land in `tcp_hash_find`
        // with one probe instead of a 128-slot linear scan.
        let key = tcp_hash_key(src_ip, src_port, dst_port);
        tcp_hash_insert(core, key, slot);

        // Send SYN+ACK
        {
            let c = unsafe { &*conn_ptr(core, slot) };
            send_segment(src_ip, dst_port, src_port, c.snd_nxt, c.rcv_nxt, TCP_SYN | TCP_ACK, RX_BUF_SIZE as u16, &[]);
        }
        unsafe {
            let cp = conn_ptr(core, slot);
            (*cp).snd_nxt = (*cp).snd_nxt.wrapping_add(1);
        }
        return;
    }

    // O(1) hash lookup by 4-tuple (replaces an O(128) linear scan
    // that used to dominate cost on the RX hot path under
    // wrk-c128 load). Also verify state — the linear scan used to
    // filter out Closed/Listen implicitly; with the hash we must
    // guard against stale entries left behind if any transition to
    // Closed took a path that skipped `free_connection`.
    let key = tcp_hash_key(src_ip, src_port, dst_port);
    let slot = match tcp_hash_find(core, key) {
        Some(s) => s,
        None => return,
    };
    {
        let c = unsafe { &*conn_ptr(core, slot) };
        if c.state == TcpState::Closed || c.state == TcpState::Listen {
            return;
        }
    }

    let c = unsafe { &mut *conn_ptr(core, slot) };

    // Process ACK
    if flags & TCP_ACK != 0 {
        if c.state == TcpState::SynReceived {
            c.state = TcpState::Established;
            c.snd_una = ack;
            // Wake any async `TcpListener::accept` awaiting on this
            // port. Runs on the core that received the 3-way-ACK,
            // which is the same core that owns this conn slot, so
            // the reactor's per-worker waker fires the right task.
            let port = c.listener_port;
            uni_runtime::net::deliver_tcp_ready(port);
        } else if c.state == TcpState::LastAck {
            free_connection(core, slot);
            return;
        } else {
            c.snd_una = ack;
        }
    }

    // Process data
    if payload_len > 0 && (c.state == TcpState::Established || c.state == TcpState::FinWait1 || c.state == TcpState::FinWait2) {
        if seq == c.rcv_nxt {
            let pushed = c.rx_push(&payload[..payload_len]);
            c.rcv_nxt = c.rcv_nxt.wrapping_add(pushed as u32);
            c.rcv_wnd = c.rx_free() as u16;
            // Wake any `TcpRecvReady` parked on this conn. Same core
            // owns the waker and the rx ring, so no cross-core hop.
            if pushed > 0 {
                if let Some(w) = c.recv_waker.take() {
                    w.wake();
                }
            }
            // Send an immediate ACK. The previous version of this code
            // deferred ACKs to piggyback on the next outbound data
            // segment (avoiding a stall on macOS's delayed-ACK
            // interaction with our own output), but that assumed the
            // app would always have outbound data to send right after
            // receiving input — true on keep-alive /health requests,
            // false on the TLS handshake path where the server has no
            // imminent response after receiving, say, the client's
            // Finished. Without an immediate ACK here the Linux peer
            // waits out its delayed-ACK timer (~40ms) before sending
            // its next handshake record, which capped GCP KVM's
            // `tls_handshake_max` at ~20 hs/s.
            //
            // The immediate ACK does double segment count on the pure
            // receive path (one ACK + one eventual data segment,
            // rather than one data segment carrying the ACK), which
            // on our existing benches costs ~2-3 % on
            // `health_max` / `health_tls_max` — well worth eating to
            // unbreak the handshake path. If the macOS delayed-ACK
            // regression from the old comment shows up again we'll
            // want a real timer-based ACK coalescer rather than
            // pinning this to "next data segment".
            send_segment(src_ip, dst_port, src_port, c.snd_nxt, c.rcv_nxt, TCP_ACK, c.rx_free() as u16, &[]);
        } else if seq_lt(seq, c.rcv_nxt) {
            // Duplicate/retransmitted segment — send ACK immediately so the
            // sender knows we already have this data (fast retransmit signal).
            send_segment(src_ip, dst_port, src_port, c.snd_nxt, c.rcv_nxt, TCP_ACK, c.rx_free() as u16, &[]);
        }
    }

    // Process FIN.
    //
    // A FIN is in-sequence iff its own seq number (seq + payload_len)
    // equals our current rcv_nxt. Anything else — including an
    // off-path FIN with a guessed seq or a delayed retransmission
    // whose FIN was already consumed — is ignored. Advancing rcv_nxt
    // unconditionally (as the previous version did) let any FIN-bit
    // segment close the connection and desync the receive stream.
    if flags & TCP_FIN != 0 && seq.wrapping_add(payload_len as u32) == c.rcv_nxt {
        c.rcv_nxt = c.rcv_nxt.wrapping_add(1);
        send_segment(src_ip, dst_port, src_port, c.snd_nxt, c.rcv_nxt, TCP_ACK, c.rx_free() as u16, &[]);

        match c.state {
            TcpState::Established | TcpState::SynReceived => {
                c.state = TcpState::CloseWait;
            }
            TcpState::FinWait1 => {
                free_connection(core, slot);
            }
            TcpState::FinWait2 => {
                free_connection(core, slot);
            }
            _ => {}
        }
        // Peer FIN is also a readable-state transition: any pending
        // `recv_ready` must resolve so the handler can observe the
        // close via `is_closed()` / `recv() == 0`. `free_connection`
        // above already resets the whole conn (including `recv_waker`)
        // via `TcpConnection::new()`; in the CloseWait branch we still
        // hold the waker, so fire it here.
        if c.state == TcpState::CloseWait {
            if let Some(w) = c.recv_waker.take() {
                w.wake();
            }
        }
    }
}

fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

// ============================================================================
// TCP public API — handles encode (core, slot) for transparent routing.
// ============================================================================

/// Initialize TCP connection pools.
pub fn init() {
    for core in 0..MAX_CORES {
        for i in 0..CONNECTIONS_PER_CORE {
            unsafe { *conn_ptr(core as u32, i) = TcpConnection::new(); }
        }
    }
}

/// Create a listener on the current core.
pub fn listen(port: u16) -> *mut () {
    listen_on_core(uni_kernel::cpu_id(), port)
}

/// Create a listener on a specific core.
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

/// Accept a connection from a specific core's pool.
pub fn accept(handle: *mut ()) -> *mut () {
    let (core, listener_slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return ptr::null_mut(),
    };
    let port = unsafe { (*conn_ptr(core, listener_slot)).local_port };
    accept_on_port_core(core, port)
}

/// Accept a connection on the **current core** by port — the
/// listener handle isn't threaded through, so this is the entry
/// point used by `uni_runtime::net::TcpListener`'s backend hook.
/// Returns null if no connection is ready on this core.
pub fn accept_on_port(port: u16) -> *mut () {
    accept_on_port_core(uni_kernel::cpu_id(), port)
}

fn accept_on_port_core(core: u32, port: u16) -> *mut () {
    for i in 0..CONNECTIONS_PER_CORE {
        // SAFETY: per-core ownership.
        let c = unsafe { &mut *conn_ptr(core, i) };
        if c.state == TcpState::Established && c.listener_port == port && !c.accepted {
            c.accepted = true;
            return encode_handle(core, i);
        }
    }
    ptr::null_mut()
}

pub fn has_data(handle: *mut ()) -> bool {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return false,
    };
    unsafe { (*conn_ptr(core, slot)).rx_used() > 0 }
}

pub fn recv(handle: *mut (), buf: &mut [u8]) -> usize {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return 0,
    };
    unsafe { (*conn_ptr(core, slot)).rx_pop(buf) }
}

pub fn send(handle: *mut (), data: &[u8]) -> i32 {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return -1,
    };
    // SAFETY: per-core ownership.
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.state != TcpState::Established {
        return -1;
    }

    let len = data.len();
    let mut sent = 0;
    while sent < len {
        let chunk = (len - sent).min(MSS);
        send_segment(
            c.remote_ip,
            c.local_port,
            c.remote_port,
            c.snd_nxt,
            c.rcv_nxt,
            TCP_ACK | TCP_PSH,
            c.rx_free() as u16,
            &data[sent..sent + chunk],
        );
        c.snd_nxt = c.snd_nxt.wrapping_add(chunk as u32);
        sent += chunk;
    }
    sent as i32
}

pub fn close(handle: *mut ()) {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return,
    };
    // SAFETY: per-core ownership.
    let c = unsafe { &mut *conn_ptr(core, slot) };
    match c.state {
        TcpState::Established => {
            send_segment(
                c.remote_ip, c.local_port, c.remote_port,
                c.snd_nxt, c.rcv_nxt, TCP_FIN | TCP_ACK, 0, &[],
            );
            c.snd_nxt = c.snd_nxt.wrapping_add(1);
            c.state = TcpState::FinWait1;
        }
        TcpState::CloseWait => {
            send_segment(
                c.remote_ip, c.local_port, c.remote_port,
                c.snd_nxt, c.rcv_nxt, TCP_FIN | TCP_ACK, 0, &[],
            );
            free_connection(core, slot);
            return;
        }
        _ => {
            free_connection(core, slot);
        }
    }
}

/// Park the current task's waker on this conn, to be woken when
/// data arrives or the peer FINs. Called from
/// `uni_runtime::net::TcpRecvReady::poll` on the owning core.
pub fn register_recv_waker(handle: *mut (), waker: &Waker) {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => { waker.wake_by_ref(); return; }
    };
    let c = unsafe { &mut *conn_ptr(core, slot) };
    match &c.recv_waker {
        Some(w) if w.will_wake(waker) => {}
        _ => c.recv_waker = Some(waker.clone()),
    }
}

/// Drop the parked waker without firing it. Called from
/// `TcpRecvReady::poll` after resolving Ready so a subsequent data
/// arrival doesn't wake a no-longer-interested task.
pub fn clear_recv_waker(handle: *mut ()) {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return,
    };
    let c = unsafe { &mut *conn_ptr(core, slot) };
    c.recv_waker = None;
}

pub fn is_closed(handle: *mut ()) -> bool {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return true,
    };
    let c = unsafe { &*conn_ptr(core, slot) };
    // Closed: connection fully terminated.
    // CloseWait with empty RX: client sent FIN, data consumed.
    // LastAck: we sent FIN, waiting for final ACK. Treat as closed
    // to prevent pool exhaustion (the ACK may never arrive).
    c.state == TcpState::Closed
        || (c.state == TcpState::CloseWait && c.rx_used() == 0)
}
