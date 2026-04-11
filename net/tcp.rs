// net/tcp.rs — TCP state machine, per-core connection pool, ring buffers.
//
// Connections are partitioned across cores. Each core owns a slice of
// the global pool. The flow hash (in net/lib.rs) routes packets to the
// owning core. All connection operations are core-local — no locks.

#![no_std]

extern crate kernel;
extern crate net_from_bytes as from_bytes;
extern crate net_types as types;
extern crate net_ipv4 as ipv4;
extern crate bitflags;

use core::ptr;
use from_bytes::FromBytes;
use kernel::kbox::KBox;
use types::{Ipv4Addr, CONFIG, tcp_checksum, htons, ntohs, htonl, ntohl};
use ipv4::{ipv4_send, PROTO_TCP};

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

const CONNECTIONS_PER_CORE: usize = 32;
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
    /// (allocated in `tcp_receive` SYN handling), then a `KBox<[u8]>`
    /// of length `RX_BUF_SIZE`. Drop runs `kfree` automatically when
    /// the connection is reset, eliminating the manual `kfree` that
    /// the previous `*mut u8` field required.
    rx_buf: Option<KBox<[u8]>>,
    rx_head: usize,
    rx_tail: usize,
    listener_port: u16,
    accepted: bool,
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
// `kernel::percpu::PerCpu`, which provides typed `current(&CurrentCore)`
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

static POOLS: kernel::percpu::PerCpu<CoreSlots, MAX_CORES> =
    kernel::percpu::PerCpu::new(
        [const { [const { TcpConnCell::new() }; CONNECTIONS_PER_CORE] }; MAX_CORES],
    );

/// Get a `*mut TcpConnection` for `(core, slot)`. The caller must
/// uphold the per-core ownership discipline (only the owning core may
/// dereference the resulting pointer mutably).
#[inline]
fn conn_ptr(core: u32, slot: usize) -> *mut TcpConnection {
    POOLS.at(core)[slot].0.get()
}

/// TCP initial-sequence-number counter.
static SEQ_COUNTER: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(100_000);

#[inline]
fn next_seq() -> u32 {
    SEQ_COUNTER.fetch_add(64_000, core::sync::atomic::Ordering::Relaxed)
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
    // Assigning a fresh TcpConnection drops the old one, which runs
    // the Drop impl on `rx_buf: Option<KBox<[u8]>>` — KBox::drop calls
    // kfree. No manual kfree needed.
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
    let core = kernel::cpu_id();

    // SAFETY for the closures below: per-core ownership — only this
    // core (== `core`) is touching POOLS[core][*].

    // RST handling
    if flags & TCP_RST != 0 {
        for i in 0..CONNECTIONS_PER_CORE {
            let c = unsafe { &*conn_ptr(core, i) };
            if c.state != TcpState::Closed
                && c.state != TcpState::Listen
                && c.remote_ip == src_ip
                && c.local_port == dst_port
                && c.remote_port == src_port
            {
                free_connection(core, i);
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

            // Allocate RX buffer. KBox handles kmalloc + auto-kfree;
            // no manual free is needed when the connection is reset.
            c.rx_buf = KBox::<[u8]>::try_new_zeroed_slice(RX_BUF_SIZE);
            c.rx_head = 0;
            c.rx_tail = 0;
        }

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

    // Find existing connection on this core
    let conn_slot = {
        let mut found = None;
        for i in 0..CONNECTIONS_PER_CORE {
            let c = unsafe { &*conn_ptr(core, i) };
            if c.state != TcpState::Closed
                && c.state != TcpState::Listen
                && c.remote_ip == src_ip
                && c.local_port == dst_port
                && c.remote_port == src_port
            {
                found = Some(i);
                break;
            }
        }
        found
    };

    let slot = match conn_slot {
        Some(i) => i,
        None => return,
    };

    let c = unsafe { &mut *conn_ptr(core, slot) };

    // Process ACK
    if flags & TCP_ACK != 0 {
        if c.state == TcpState::SynReceived {
            c.state = TcpState::Established;
            c.snd_una = ack;
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
            // Defer ACK — it will be piggybacked on the next outgoing data
            // segment (the HTTP response). Sending a separate pure ACK here
            // doubles the segment count and triggers macOS delayed-ACK
            // interactions that cause ~250ms stalls on keep-alive connections.
        } else if seq_lt(seq, c.rcv_nxt) {
            // Duplicate/retransmitted segment — send ACK immediately so the
            // sender knows we already have this data (fast retransmit signal).
            send_segment(src_ip, dst_port, src_port, c.snd_nxt, c.rcv_nxt, TCP_ACK, c.rx_free() as u16, &[]);
        }
    }

    // Process FIN
    if flags & TCP_FIN != 0 {
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
    listen_on_core(kernel::cpu_id(), port)
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
