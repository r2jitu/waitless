// net/tcp.rs — TCP state machine, connection pool, ring buffers.

use core::ptr;

use kernel::mm as kernel_mm;

use crate::types::{Ipv4Addr, CONFIG, tcp_checksum};
use crate::ipv4::{ipv4_send, PROTO_TCP};
use crate::ethernet::ethernet_receive;
use crate::{htons, ntohs, htonl, ntohl};

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

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

const MAX_CONNECTIONS: usize = 128;
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
    rx_buf: *mut u8,
    rx_buf_size: usize,
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
            rx_buf: ptr::null_mut(),
            rx_buf_size: 0,
            rx_head: 0,
            rx_tail: 0,
            listener_port: 0,
            accepted: false,
        }
    }

    fn rx_used(&self) -> usize {
        if self.rx_head >= self.rx_tail {
            self.rx_head - self.rx_tail
        } else {
            self.rx_buf_size - self.rx_tail + self.rx_head
        }
    }

    fn rx_free(&self) -> usize {
        self.rx_buf_size - 1 - self.rx_used()
    }

    fn rx_push(&mut self, data: &[u8]) -> usize {
        let free = self.rx_free();
        let n = data.len().min(free);
        for i in 0..n {
            unsafe { *self.rx_buf.add(self.rx_head) = data[i] };
            self.rx_head = (self.rx_head + 1) % self.rx_buf_size;
        }
        n
    }

    fn rx_pop(&mut self, buf: &mut [u8]) -> usize {
        let used = self.rx_used();
        let n = buf.len().min(used);
        // Optimize: contiguous read from tail
        let contig = self.rx_buf_size - self.rx_tail;
        if n <= contig {
            unsafe { ptr::copy_nonoverlapping(self.rx_buf.add(self.rx_tail), buf.as_mut_ptr(), n) };
        } else {
            unsafe {
                ptr::copy_nonoverlapping(self.rx_buf.add(self.rx_tail), buf.as_mut_ptr(), contig);
                ptr::copy_nonoverlapping(self.rx_buf, buf.as_mut_ptr().add(contig), n - contig);
            }
        }
        self.rx_tail = (self.rx_tail + n) % self.rx_buf_size;
        n
    }
}

static mut CONNECTIONS: [TcpConnection; MAX_CONNECTIONS] =
    [const { TcpConnection::new() }; MAX_CONNECTIONS];
static mut SEQ_COUNTER: u32 = 100_000;

static mut TCP_SEG_BUF: [u8; 20 + MSS] = [0; 20 + MSS];
static mut TCP_RST_BUF: [u8; 20] = [0; 20];

fn alloc_connection() -> Option<usize> {
    unsafe {
        for i in 0..MAX_CONNECTIONS {
            if CONNECTIONS[i].state == TcpState::Closed {
                CONNECTIONS[i] = TcpConnection::new();
                return Some(i);
            }
        }
        None
    }
}

fn free_connection(idx: usize) {
    unsafe {
        if !CONNECTIONS[idx].rx_buf.is_null() {
            kernel_mm::kfree(CONNECTIONS[idx].rx_buf);
        }
        CONNECTIONS[idx] = TcpConnection::new();
    }
}

fn send_segment(
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) {
    let payload_len = payload.len().min(MSS);
    let seg_len = 20 + payload_len;

    unsafe {
        let hdr = &mut *(TCP_SEG_BUF.as_mut_ptr() as *mut TcpHeader);
        hdr.src_port = htons(src_port);
        hdr.dst_port = htons(dst_port);
        hdr.seq = htonl(seq);
        hdr.ack = htonl(ack);
        hdr.data_offset = 0x50; // 5 words = 20 bytes
        hdr.flags = flags;
        hdr.window = htons(RX_BUF_SIZE as u16);
        hdr.checksum = 0;
        hdr.urgent = 0;

        if !payload.is_empty() {
            ptr::copy_nonoverlapping(
                payload.as_ptr(),
                TCP_SEG_BUF.as_mut_ptr().add(20),
                payload_len,
            );
        }

        hdr.checksum = tcp_checksum(
            CONFIG.ip,
            dst_ip,
            PROTO_TCP,
            TCP_SEG_BUF.as_ptr(),
            seg_len,
        );

        ipv4_send(dst_ip, PROTO_TCP, &TCP_SEG_BUF[..seg_len]);
    }
}

fn send_rst(dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, seq: u32, ack: u32) {
    unsafe {
        let hdr = &mut *(TCP_RST_BUF.as_mut_ptr() as *mut TcpHeader);
        hdr.src_port = htons(src_port);
        hdr.dst_port = htons(dst_port);
        hdr.seq = htonl(seq);
        hdr.ack = htonl(ack);
        hdr.data_offset = 0x50;
        hdr.flags = TCP_RST | TCP_ACK;
        hdr.window = 0;
        hdr.checksum = 0;
        hdr.urgent = 0;

        hdr.checksum = tcp_checksum(CONFIG.ip, dst_ip, PROTO_TCP, TCP_RST_BUF.as_ptr(), 20);

        ipv4_send(dst_ip, PROTO_TCP, &TCP_RST_BUF[..20]);
    }
}

pub(crate) fn tcp_receive(src_ip: Ipv4Addr, _dst_ip: Ipv4Addr, data: *const u8, len: usize) {
    if len < 20 {
        return;
    }
    let hdr = unsafe { &*(data as *const TcpHeader) };
    let src_port = ntohs(hdr.src_port);
    let dst_port = ntohs(hdr.dst_port);
    let seq = ntohl(hdr.seq);
    let ack = ntohl(hdr.ack);
    let flags = hdr.flags;
    let data_offset = ((hdr.data_offset >> 4) as usize) * 4;
    let payload_len = if len > data_offset { len - data_offset } else { 0 };
    let payload = unsafe { data.add(data_offset) };

    // RST handling
    if flags & TCP_RST != 0 {
        unsafe {
            for i in 0..MAX_CONNECTIONS {
                let c = &mut CONNECTIONS[i];
                if c.state != TcpState::Closed
                    && c.state != TcpState::Listen
                    && c.remote_ip == src_ip
                    && c.local_port == dst_port
                    && c.remote_port == src_port
                {
                    free_connection(i);
                    return;
                }
            }
        }
        return;
    }

    // SYN — new connection from client
    if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 {
        // Find listener
        let listener_idx = unsafe {
            let mut found = None;
            for i in 0..MAX_CONNECTIONS {
                if CONNECTIONS[i].state == TcpState::Listen && CONNECTIONS[i].local_port == dst_port
                {
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

        // Allocate new connection
        let idx = match alloc_connection() {
            Some(i) => i,
            None => return,
        };

        unsafe {
            let c = &mut CONNECTIONS[idx];
            c.state = TcpState::SynReceived;
            c.remote_ip = src_ip;
            c.local_port = dst_port;
            c.remote_port = src_port;
            SEQ_COUNTER = SEQ_COUNTER.wrapping_add(64000);
            c.snd_nxt = SEQ_COUNTER;
            c.snd_una = c.snd_nxt;
            c.rcv_nxt = seq + 1;
            c.listener_port = dst_port;
            c.accepted = false;

            // Allocate RX buffer
            c.rx_buf = kernel_mm::kmalloc(RX_BUF_SIZE);
            c.rx_buf_size = RX_BUF_SIZE;
            c.rx_head = 0;
            c.rx_tail = 0;
        }

        // Send SYN+ACK
        unsafe {
            let c = &CONNECTIONS[idx];
            send_segment(src_ip, dst_port, src_port, c.snd_nxt, c.rcv_nxt, TCP_SYN | TCP_ACK, &[]);
            CONNECTIONS[idx].snd_nxt = CONNECTIONS[idx].snd_nxt.wrapping_add(1);
        }
        return;
    }

    // Find existing connection
    let conn_idx = unsafe {
        let mut found = None;
        for i in 0..MAX_CONNECTIONS {
            let c = &CONNECTIONS[i];
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

    let idx = match conn_idx {
        Some(i) => i,
        None => return,
    };

    unsafe {
        let c = &mut CONNECTIONS[idx];

        // Process ACK
        if flags & TCP_ACK != 0 {
            if c.state == TcpState::SynReceived {
                c.state = TcpState::Established;
                c.snd_una = ack;
            } else {
                c.snd_una = ack;
            }
        }

        // Process data
        if payload_len > 0 && (c.state == TcpState::Established || c.state == TcpState::FinWait1 || c.state == TcpState::FinWait2) {
            if seq == c.rcv_nxt {
                // In-order data
                let pushed = c.rx_push(core::slice::from_raw_parts(payload, payload_len));
                c.rcv_nxt = c.rcv_nxt.wrapping_add(pushed as u32);
                c.rcv_wnd = c.rx_free() as u16;
                // ACK
                send_segment(src_ip, dst_port, src_port, c.snd_nxt, c.rcv_nxt, TCP_ACK, &[]);
            } else if seq_lt(seq, c.rcv_nxt) {
                // Duplicate — resend ACK
                send_segment(src_ip, dst_port, src_port, c.snd_nxt, c.rcv_nxt, TCP_ACK, &[]);
            }
            // Out of order: silently drop
        }

        // Process FIN
        if flags & TCP_FIN != 0 {
            c.rcv_nxt = c.rcv_nxt.wrapping_add(1);
            send_segment(src_ip, dst_port, src_port, c.snd_nxt, c.rcv_nxt, TCP_ACK, &[]);

            match c.state {
                TcpState::Established | TcpState::SynReceived => {
                    c.state = TcpState::CloseWait;
                }
                TcpState::FinWait1 => {
                    // Simultaneous close: FIN received in FinWait1 → TimeWait.
                    // Simplified: skip TimeWait timer and free immediately.
                    free_connection(idx);
                }
                TcpState::FinWait2 => {
                    // TIME_WAIT → immediate close (simplified)
                    free_connection(idx);
                }
                _ => {}
            }
        }
    }
}

/// Compare TCP sequence numbers (handles wraparound).
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

// ============================================================================
// TCP public API
// ============================================================================

/// Initialize TCP connection pool.
pub fn tcp_init() {
    unsafe {
        for i in 0..MAX_CONNECTIONS {
            CONNECTIONS[i] = TcpConnection::new();
        }
    }
}

pub fn tcp_listen(port: u16) -> *mut () {
    let idx = match alloc_connection() {
        Some(i) => i,
        None => return ptr::null_mut(),
    };
    unsafe {
        CONNECTIONS[idx].state = TcpState::Listen;
        CONNECTIONS[idx].local_port = port;
        // Return connection index encoded as pointer (1-based to avoid null)
        (idx + 1) as *mut ()
    }
}

pub fn tcp_accept(handle: *mut ()) -> *mut () {
    let listener_idx = (handle as usize) - 1;
    if listener_idx >= MAX_CONNECTIONS {
        return ptr::null_mut();
    }

    unsafe {
        let port = CONNECTIONS[listener_idx].local_port;
        for i in 0..MAX_CONNECTIONS {
            let c = &mut CONNECTIONS[i];
            if c.state == TcpState::Established && c.listener_port == port && !c.accepted {
                c.accepted = true;
                return (i + 1) as *mut ();
            }
        }
    }
    ptr::null_mut()
}

pub fn tcp_has_data(handle: *mut ()) -> bool {
    let idx = (handle as usize) - 1;
    if idx >= MAX_CONNECTIONS {
        return false;
    }
    unsafe { CONNECTIONS[idx].rx_used() > 0 }
}

pub fn tcp_recv(handle: *mut (), buf: &mut [u8]) -> usize {
    let idx = (handle as usize) - 1;
    if idx >= MAX_CONNECTIONS {
        return 0;
    }
    unsafe { CONNECTIONS[idx].rx_pop(buf) }
}

pub fn tcp_send(handle: *mut (), data: &[u8]) -> i32 {
    let idx = (handle as usize) - 1;
    if idx >= MAX_CONNECTIONS {
        return -1;
    }
    unsafe {
        let c = &mut CONNECTIONS[idx];
        if c.state != TcpState::Established {
            return -1;
        }

        // Send in MSS-sized chunks
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
                &data[sent..sent + chunk],
            );
            c.snd_nxt = c.snd_nxt.wrapping_add(chunk as u32);
            sent += chunk;
        }
        sent as i32
    }
}

pub fn tcp_close(handle: *mut ()) {
    let idx = (handle as usize) - 1;
    if idx >= MAX_CONNECTIONS {
        return;
    }
    unsafe {
        let c = &mut CONNECTIONS[idx];
        match c.state {
            TcpState::Established => {
                // Send FIN
                send_segment(
                    c.remote_ip, c.local_port, c.remote_port,
                    c.snd_nxt, c.rcv_nxt, TCP_FIN | TCP_ACK, &[],
                );
                c.snd_nxt = c.snd_nxt.wrapping_add(1);
                c.state = TcpState::FinWait1;
            }
            TcpState::CloseWait => {
                send_segment(
                    c.remote_ip, c.local_port, c.remote_port,
                    c.snd_nxt, c.rcv_nxt, TCP_FIN | TCP_ACK, &[],
                );
                c.snd_nxt = c.snd_nxt.wrapping_add(1);
                c.state = TcpState::LastAck;
            }
            _ => {
                free_connection(idx);
            }
        }
    }
}

pub fn tcp_is_closed(handle: *mut ()) -> bool {
    let idx = (handle as usize) - 1;
    if idx >= MAX_CONNECTIONS {
        return true;
    }
    unsafe { CONNECTIONS[idx].state == TcpState::Closed }
}

pub fn tcp_poll() {
    drivers::virtio_net_poll(ethernet_receive);
}
