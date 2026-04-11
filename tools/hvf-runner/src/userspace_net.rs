// tools/hvf-runner/src/userspace_net.rs
//
// Userspace TCP/IP proxy — zero-copy, no intermediate buffers.
//
// RX thread: poll() on sockets → construct frames directly in guest
//   RAM (virtio used ring) → assert SPI 35 to wake guest.
// vCPU thread: on TX QUEUE_NOTIFY → read frames from guest RAM →
//   write() directly to host sockets.
//
// No SPSC rings, no wake pipe, no Mutex on the hot path.

use std::collections::VecDeque;
use std::sync::Mutex;

use crate::hvf;
use crate::virtio;

const VIRTIO_NET_HDR_SIZE: usize = 12;
const GW_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const VM_IP: [u8; 4] = [10, 0, 2, 15];
const GW_IP: [u8; 4] = [10, 0, 2, 2];
const BROADCAST_IP: [u8; 4] = [255, 255, 255, 255];

/// Per-connection state. Fields are split by ownership:
/// - host_fd, src_port: set once at accept, immutable after.
/// - state: AtomicU8, transitions 0→1→2 (written by vCPU on SYN-ACK, read by IO for poll).
/// - my_seq, peer_ack: written only by vCPU (TX path), read only by IO (RX inject ACKs).
/// - pending: written by IO (buffered data before ESTABLISHED), read/drained by vCPU.
///
/// No Mutex needed on the hot path — fields are either immutable, atomic,
/// or accessed by only one thread at a time.
/// Shared connection state — no Mutex, just atomics.
/// Immutable after init: host_fd, src_port.
/// Atomic: state (0→1→2), my_seq, peer_ack.
struct ProxyConn {
    host_fd: i32,
    src_port: u16,
    state: std::sync::atomic::AtomicU8,
    my_seq: std::sync::atomic::AtomicU32,
    peer_ack: std::sync::atomic::AtomicU32,
}

const MAX_CONNS: usize = 128;
/// Fixed-size connection table. New connections are appended via CONN_COUNT.
/// No Mutex for iteration — IO thread and vCPU read concurrently.
static CONN_SLOTS: [std::sync::OnceLock<ProxyConn>; MAX_CONNS] = [const { std::sync::OnceLock::new() }; MAX_CONNS];
static CONN_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static RX_LAST: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

fn alloc_conn(host_fd: i32, src_port: u16) -> Option<usize> {
    let idx = CONN_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if idx >= MAX_CONNS { return None; }
    let _ = CONN_SLOTS[idx].set(ProxyConn {
        host_fd, src_port,
        state: std::sync::atomic::AtomicU8::new(0),
        my_seq: std::sync::atomic::AtomicU32::new(1001),
        peer_ack: std::sync::atomic::AtomicU32::new(0),
    });
    Some(idx)
}

fn find_conn(src_port: u16) -> Option<&'static ProxyConn> {
    let n = CONN_COUNT.load(std::sync::atomic::Ordering::Relaxed);
    for i in 0..n {
        if let Some(c) = CONN_SLOTS[i].get() {
            if c.src_port == src_port { return Some(c); }
        }
    }
    None
}

struct IoState {
    listen_fd: i32,
    next_port: u16,
    guest_mac: [u8; 6],
    read_buf: [u8; 2048],
    reply_queue: VecDeque<Vec<u8>>,
    pending: std::collections::HashMap<u16, Vec<u8>>,  // src_port → buffered data (pre-ESTABLISHED)
}

pub fn start(port: u16) -> Result<[u8; 6], String> {
    let mac: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    let listen_fd = unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 { return Err("socket() failed".into()); }
        let one: i32 = 1;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR,
                         &one as *const _ as *const _, 4);
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as u8;
        addr.sin_port = port.to_be();
        addr.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();
        if libc::bind(fd, &addr as *const _ as *const _, std::mem::size_of_val(&addr) as u32) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(format!("bind({port}): {e}"));
        }
        libc::listen(fd, 128);
        libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
        fd
    };
    std::thread::spawn(move || { io_thread(listen_fd, mac); });
    eprintln!();
    eprintln!("  VM network: 10.0.2.15 (userspace, zero-copy)");
    eprintln!("  Benchmark:  wrk -t1 -c1 -d10s http://localhost:{port}/health");
    eprintln!();
    Ok(mac)
}

pub fn check_rx() {}
pub fn flush_rx_into(_dev: &mut virtio::VirtioNet) {}

pub fn process_tx() {
    let mut dev_lock = virtio::DEVICE.lock().unwrap();
    let dev = match dev_lock.as_mut() { Some(d) => d, None => return };
    let q = dev.queue(1);
    if !q.ready { return; }
    let desc_base = q.desc_addr();
    let avail_base = q.avail_addr();
    let used_base = q.used_addr();
    let qsize = q.num as u16;
    if qsize == 0 { return; }
    let avail_idx = unsafe {
        core::ptr::read_volatile(dev.gpa_to_host(avail_base + 2) as *const u16)
    };
    static TX_LAST: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
    let mut last = TX_LAST.load(std::sync::atomic::Ordering::Relaxed);
    while last != avail_idx {
        let ring_idx = last & (qsize - 1);
        let desc_idx = unsafe {
            core::ptr::read_volatile(
                dev.gpa_to_host(avail_base + 4 + ring_idx as u64 * 2) as *const u16)
        };
        let (addr, len) = unsafe {
            let dp = dev.gpa_to_host(desc_base + desc_idx as u64 * 16);
            (core::ptr::read_unaligned(dp as *const u64),
             core::ptr::read_unaligned(dp.add(8) as *const u32) as usize)
        };
        if len > VIRTIO_NET_HDR_SIZE {
            let frame = unsafe {
                std::slice::from_raw_parts(
                    dev.gpa_to_host(addr).add(VIRTIO_NET_HDR_SIZE),
                    len - VIRTIO_NET_HDR_SIZE)
            };
            handle_guest_tx(frame);
        }
        let used_idx = unsafe {
            core::ptr::read_volatile(dev.gpa_to_host(used_base + 2) as *const u16)
        };
        unsafe {
            let entry = dev.gpa_to_host(used_base + 4 + (used_idx & (qsize - 1)) as u64 * 8);
            core::ptr::write_unaligned(entry as *mut u32, desc_idx as u32);
            core::ptr::write_unaligned(entry.add(4) as *mut u32, len as u32);
            core::ptr::write_volatile(dev.gpa_to_host(used_base + 2) as *mut u16,
                used_idx.wrapping_add(1));
        }
        last = last.wrapping_add(1);
    }
    TX_LAST.store(last, std::sync::atomic::Ordering::Relaxed);
    dev.interrupt_status |= 1;
    unsafe { core::arch::asm!("dsb sy", options(nostack)); }
    drop(dev_lock);
    unsafe { hvf::hv_gic_set_spi(35, true); }
}

// ── IO / RX thread ──────────────────────────────────────────────────────────

fn io_thread(listen_fd: i32, mac: [u8; 6]) {
    use std::sync::atomic::Ordering::Relaxed;
    let mut io = IoState {
        listen_fd, next_port: 40000, guest_mac: mac,
        read_buf: [0u8; 2048], reply_queue: VecDeque::new(),
        pending: std::collections::HashMap::new(),
    };
    io.reply_queue.push_back(build_grat_arp(&mac));

    loop {
        let snap = virtio::rx_queue_snapshot();
        if snap.ready { flush_reply_queue(&mut io, &snap); }

        // Build pollfds from lock-free connection table.
        let n = CONN_COUNT.load(Relaxed);
        let mut pollfds: Vec<libc::pollfd> = Vec::with_capacity(1 + n);
        pollfds.push(libc::pollfd { fd: listen_fd, events: libc::POLLIN, revents: 0 });
        for i in 0..n {
            if let Some(c) = CONN_SLOTS[i].get() {
                let st = c.state.load(Relaxed);
                pollfds.push(libc::pollfd {
                    fd: if c.host_fd >= 0 && st < 2 { c.host_fd } else { -1 },
                    events: libc::POLLIN, revents: 0,
                });
            } else {
                pollfds.push(libc::pollfd { fd: -1, events: 0, revents: 0 });
            }
        }

        // Flush pending data for connections that just became ESTABLISHED.
        let pending_ports: Vec<u16> = io.pending.keys().copied().collect();
        for port in pending_ports {
            if let Some(c) = find_conn(port) {
                if c.state.load(Relaxed) == 1 {
                    if let Some(data) = io.pending.remove(&port) {
                        if snap.ready {
                            inject_data_frames_atomic(c, &data, &io.guest_mac, &snap);
                            unsafe { core::arch::asm!("dsb sy", options(nostack)); }
                            unsafe { hvf::hv_gic_set_spi(35, true); }
                        }
                    }
                }
            }
        }

        let ready = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as u32, 5) };
        if ready <= 0 { continue; }

        if pollfds[0].revents & libc::POLLIN != 0 {
            accept_connections(&mut io, &snap);
        }

        let mut injected = false;
        for i in 0..n {
            if i + 1 >= pollfds.len() { break; }
            if pollfds[i + 1].revents & (libc::POLLIN | libc::POLLHUP) == 0 { continue; }
            let c = match CONN_SLOTS[i].get() { Some(c) => c, None => continue };
            if c.host_fd < 0 { continue; }
            let nr = unsafe {
                libc::read(c.host_fd, io.read_buf.as_mut_ptr() as *mut _, io.read_buf.len())
            };
            if nr == 0 {
                if c.state.load(Relaxed) == 1 {
                    let frame = build_tcp_frame(&io.guest_mac, GW_IP, VM_IP,
                        c.src_port, 80,
                        c.my_seq.load(Relaxed), c.peer_ack.load(Relaxed),
                        0x11, &[]);
                    c.my_seq.fetch_add(1, Relaxed);
                    c.state.store(2, Relaxed);
                    if snap.ready { inject_frame(&frame, &snap); injected = true; }
                    else { io.reply_queue.push_back(frame); }
                }
            } else if nr > 0 {
                let data = io.read_buf[..nr as usize].to_vec();
                let st = c.state.load(Relaxed);
                if st == 1 && snap.ready {
                    inject_data_frames_atomic(c, &data, &io.guest_mac, &snap);
                    injected = true;
                } else {
                    io.pending.entry(c.src_port).or_default().extend_from_slice(&data);
                }
            }
        }
        if injected {
            unsafe { core::arch::asm!("dsb sy", options(nostack)); }
            unsafe { hvf::hv_gic_set_spi(35, true); }
        }
    }
}

/// inject data frames using atomic seq/ack (IO thread).
fn inject_data_frames_atomic(c: &ProxyConn, data: &[u8], mac: &[u8; 6], snap: &virtio::QueueSnapshot) {
    use std::sync::atomic::Ordering::Relaxed;
    let mut off = 0;
    while off < data.len() {
        let chunk = (data.len() - off).min(1460);
        let seq = c.my_seq.load(Relaxed);
        let ack = c.peer_ack.load(Relaxed);
        let frame = build_tcp_frame(mac, GW_IP, VM_IP, c.src_port, 80,
            seq, ack, 0x18, &data[off..off + chunk]);
        c.my_seq.fetch_add(chunk as u32, Relaxed);
        off += chunk;
        inject_frame(&frame, snap);
    }
}

fn accept_connections(io: &mut IoState, snap: &virtio::QueueSnapshot) {
    loop {
        let client_fd = unsafe {
            libc::accept(io.listen_fd, std::ptr::null_mut(), std::ptr::null_mut())
        };
        if client_fd < 0 { break; }
        unsafe {
            libc::fcntl(client_fd, libc::F_SETFL, libc::O_NONBLOCK);
            let one: i32 = 1;
            libc::setsockopt(client_fd, libc::IPPROTO_TCP, libc::TCP_NODELAY,
                             &one as *const _ as *const _, 4);
        }
        let src_port = io.next_port;
        io.next_port = if io.next_port >= 59999 { 40000 } else { io.next_port + 1 };
        let frame = build_tcp_frame(&io.guest_mac, GW_IP, VM_IP,
            src_port, 80, 1000, 0, 0x02, &[]);
        if snap.ready {
            inject_frame(&frame, snap);
            unsafe { core::arch::asm!("dsb sy", options(nostack)); }
            unsafe { hvf::hv_gic_set_spi(35, true); }
        } else { io.reply_queue.push_back(frame); }
        alloc_conn(client_fd, src_port);
    }
}

fn inject_frame(frame: &[u8], snap: &virtio::QueueSnapshot) -> bool {
    let avail_idx = unsafe {
        core::ptr::read_volatile(snap.gpa_to_host(snap.avail_addr + 2) as *const u16)
    };
    let last = RX_LAST.load(std::sync::atomic::Ordering::Relaxed);
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
    }
    RX_LAST.store(last.wrapping_add(1), std::sync::atomic::Ordering::Relaxed);
    true
}

// inject_data_frames replaced by inject_data_frames_atomic above.

fn flush_reply_queue(io: &mut IoState, snap: &virtio::QueueSnapshot) {
    let mut any = false;
    while let Some(frame) = io.reply_queue.pop_front() {
        if !inject_frame(&frame, snap) { io.reply_queue.push_front(frame); break; }
        any = true;
    }
    if any {
        unsafe { core::arch::asm!("dsb sy", options(nostack)); }
        unsafe { hvf::hv_gic_set_spi(35, true); }
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
    let mut r = Vec::with_capacity(14 + 28);
    r.extend_from_slice(&guest_mac); r.extend_from_slice(&GW_MAC);
    r.extend_from_slice(&0x0806u16.to_be_bytes());
    r.extend_from_slice(&1u16.to_be_bytes()); r.extend_from_slice(&0x0800u16.to_be_bytes());
    r.push(6); r.push(4); r.extend_from_slice(&2u16.to_be_bytes());
    r.extend_from_slice(&GW_MAC); r.extend_from_slice(&GW_IP);
    r.extend_from_slice(&arp[8..14]); r.extend_from_slice(&arp[14..18]);
    let mut frame = vec![0u8; VIRTIO_NET_HDR_SIZE]; frame.extend_from_slice(&r);
    let snap = virtio::rx_queue_snapshot();
    if snap.ready && inject_frame(&frame, &snap) {
        unsafe { core::arch::asm!("dsb sy", options(nostack)); }
        unsafe { hvf::hv_gic_set_spi(35, true); }
    }
}

fn handle_ipv4(ip: &[u8]) {
    if ip.len() < 20 { return; }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    match ip[9] { 6 => handle_tcp(&ip[ihl..]), 17 => handle_udp(&ip[ihl..]), _ => {} }
}

fn handle_tcp(tcp: &[u8]) {
    use std::sync::atomic::Ordering::Relaxed;
    if tcp.len() < 20 { return; }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    let flags = tcp[13];
    let payload = if tcp.len() > data_offset { &tcp[data_offset..] } else { &[] };
    let snap = virtio::rx_queue_snapshot();

    if flags & 0x04 != 0 {
        if let Some(c) = find_conn(dst_port) { c.state.store(2, Relaxed); }
        return;
    }
    let mac: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    let c = match find_conn(dst_port) { Some(c) => c, None => return };
    match c.state.load(Relaxed) {
        0 => {
            if flags & 0x12 == 0x12 {
                c.peer_ack.store(seq.wrapping_add(1), Relaxed);
                c.state.store(1, Relaxed);
                let f = build_tcp_frame(&mac, GW_IP, VM_IP, c.src_port, 80,
                    c.my_seq.load(Relaxed), c.peer_ack.load(Relaxed), 0x10, &[]);
                if snap.ready { inject_frame(&f, &snap); }
                // Pending data is flushed by the IO thread when it sees state=1.
                if snap.ready {
                    unsafe { core::arch::asm!("dsb sy", options(nostack)); }
                    unsafe { hvf::hv_gic_set_spi(35, true); }
                }
            }
        }
        1 => {
            if !payload.is_empty() {
                c.peer_ack.store(seq.wrapping_add(payload.len() as u32), Relaxed);
                unsafe { libc::write(c.host_fd, payload.as_ptr() as *const _, payload.len()); }
                let f = build_tcp_frame(&mac, GW_IP, VM_IP, c.src_port, src_port,
                    c.my_seq.load(Relaxed), c.peer_ack.load(Relaxed), 0x10, &[]);
                if snap.ready {
                    inject_frame(&f, &snap);
                    unsafe { core::arch::asm!("dsb sy", options(nostack)); }
                    unsafe { hvf::hv_gic_set_spi(35, true); }
                }
            }
            if flags & 0x01 != 0 {
                let pa = c.peer_ack.load(Relaxed).wrapping_add(1);
                c.peer_ack.store(pa, Relaxed);
                let f = build_tcp_frame(&mac, GW_IP, VM_IP, c.src_port, src_port,
                    c.my_seq.load(Relaxed), pa, 0x11, &[]);
                c.my_seq.fetch_add(1, Relaxed);
                c.state.store(2, Relaxed);
                if snap.ready { inject_frame(&f, &snap); }
                // Don't close fd — IO thread might still read from it.
            }
        }
        _ => {}
    }
}

fn handle_udp(udp: &[u8]) {
    if udp.len() < 8 { return; }
    if u16::from_be_bytes([udp[0], udp[1]]) == 68 && u16::from_be_bytes([udp[2], udp[3]]) == 67 {
        handle_dhcp(&udp[8..]);
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
    let mut pkt = Vec::with_capacity(400);
    pkt.extend_from_slice(&[0xff; 6]); pkt.extend_from_slice(&GW_MAC);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());
    let ip_start = pkt.len(); pkt.extend_from_slice(&[0u8; 20]);
    let udp_start = pkt.len(); pkt.extend_from_slice(&[0u8; 8]);
    let bp = pkt.len(); pkt.resize(bp + 236, 0);
    pkt[bp] = 2; pkt[bp+1] = 1; pkt[bp+2] = 6;
    pkt[bp+4..bp+8].copy_from_slice(&bootp[4..8]);
    pkt[bp+16..bp+20].copy_from_slice(&VM_IP); pkt[bp+20..bp+24].copy_from_slice(&GW_IP);
    pkt[bp+28..bp+34].copy_from_slice(&guest_mac);
    pkt.extend_from_slice(&[99,130,83,99]); pkt.extend_from_slice(&[53,1,reply_type]);
    pkt.extend_from_slice(&[54,4]); pkt.extend_from_slice(&GW_IP);
    pkt.extend_from_slice(&[51,4,0,1,0x51,0x80]); pkt.extend_from_slice(&[1,4,255,255,255,0]);
    pkt.extend_from_slice(&[3,4]); pkt.extend_from_slice(&GW_IP);
    pkt.extend_from_slice(&[6,4,10,0,2,3]); pkt.push(255);
    let ul = (pkt.len() - udp_start) as u16;
    pkt[udp_start..udp_start+2].copy_from_slice(&67u16.to_be_bytes());
    pkt[udp_start+2..udp_start+4].copy_from_slice(&68u16.to_be_bytes());
    pkt[udp_start+4..udp_start+6].copy_from_slice(&ul.to_be_bytes());
    let it = (pkt.len() - ip_start) as u16;
    pkt[ip_start] = 0x45; pkt[ip_start+2..ip_start+4].copy_from_slice(&it.to_be_bytes());
    pkt[ip_start+6] = 0x40; pkt[ip_start+8] = 64; pkt[ip_start+9] = 17;
    pkt[ip_start+12..ip_start+16].copy_from_slice(&GW_IP);
    pkt[ip_start+16..ip_start+20].copy_from_slice(&BROADCAST_IP);
    let cs = ipv4_checksum(&pkt[ip_start..ip_start+20]);
    pkt[ip_start+10..ip_start+12].copy_from_slice(&cs.to_be_bytes());
    let mut frame = vec![0u8; VIRTIO_NET_HDR_SIZE]; frame.extend_from_slice(&pkt);
    let snap = virtio::rx_queue_snapshot();
    if snap.ready && inject_frame(&frame, &snap) {
        unsafe { core::arch::asm!("dsb sy", options(nostack)); }
        unsafe { hvf::hv_gic_set_spi(35, true); }
    }
}

// ── Packet construction ─────────────────────────────────────────────────────

fn build_grat_arp(mac: &[u8; 6]) -> Vec<u8> {
    let mut a = Vec::with_capacity(VIRTIO_NET_HDR_SIZE + 42);
    a.extend_from_slice(&[0u8; VIRTIO_NET_HDR_SIZE]);
    a.extend_from_slice(&[0xff; 6]); a.extend_from_slice(&GW_MAC);
    a.extend_from_slice(&0x0806u16.to_be_bytes());
    a.extend_from_slice(&1u16.to_be_bytes()); a.extend_from_slice(&0x0800u16.to_be_bytes());
    a.push(6); a.push(4); a.extend_from_slice(&2u16.to_be_bytes());
    a.extend_from_slice(&GW_MAC); a.extend_from_slice(&GW_IP);
    a.extend_from_slice(mac); a.extend_from_slice(&GW_IP); a
}

fn build_tcp_frame(dst_mac: &[u8; 6], src_ip: [u8; 4], dst_ip: [u8; 4],
    src_port: u16, dst_port: u16, seq: u32, ack: u32,
    flags: u8, payload: &[u8]) -> Vec<u8> {
    let tl = 20 + payload.len(); let it = 20 + tl;
    let mut p = Vec::with_capacity(VIRTIO_NET_HDR_SIZE + 14 + it);
    p.extend_from_slice(&[0u8; VIRTIO_NET_HDR_SIZE]);
    p.extend_from_slice(dst_mac); p.extend_from_slice(&GW_MAC);
    p.extend_from_slice(&0x0800u16.to_be_bytes());
    let is = p.len();
    p.push(0x45); p.push(0); p.extend_from_slice(&(it as u16).to_be_bytes());
    p.extend_from_slice(&[0,0,0x40,0]); p.push(64); p.push(6);
    p.extend_from_slice(&[0,0]); p.extend_from_slice(&src_ip); p.extend_from_slice(&dst_ip);
    let cs = ipv4_checksum(&p[is..is+20]);
    p[is+10] = (cs >> 8) as u8; p[is+11] = (cs & 0xff) as u8;
    let ts = p.len();
    p.extend_from_slice(&src_port.to_be_bytes()); p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes()); p.extend_from_slice(&ack.to_be_bytes());
    p.push(0x50); p.push(flags); p.extend_from_slice(&0xffffu16.to_be_bytes());
    p.extend_from_slice(&[0,0,0,0]); p.extend_from_slice(payload);
    let tc = tcp_checksum(&src_ip, &dst_ip, &p[ts..]);
    p[ts+16] = (tc >> 8) as u8; p[ts+17] = (tc & 0xff) as u8; p
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
