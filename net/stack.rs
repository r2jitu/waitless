// net/stack.rs — Bare-metal network stack (Rust, no_std)
//
// Complete TCP/IP stack for the unikernel: Ethernet, ARP, IPv4, TCP, DHCP.
// Replaces the C++ net/ethernet.cc, net/arp.cc, net/ipv4.cc, net/tcp.cc,
// net/dhcp.cc, and net/types.cc.
//
// All buffers are fixed-size, statically allocated. No heap except for
// per-connection TCP receive buffers (via kmalloc/kfree FFI).

#![no_std]
// Bare-metal single-threaded code: static mut references are safe here.
#![allow(static_mut_refs)]

use core::ptr;

// ============================================================================
// Rust crate dependencies — direct calls, no FFI
// ============================================================================

extern crate kernel_serial;
extern crate kernel_mm;
extern crate drivers;

fn log(msg: &[u8]) {
    unsafe { kernel_serial::serial_puts(msg.as_ptr()) }
}

/// Busy-wait for approximately `us` microseconds.
#[cfg(target_arch = "x86_64")]
fn arch_udelay(us: u32) {
    // Use TSC for timing. Calibrate once via PIT channel 2.
    static mut TSC_PER_US: u64 = 0;

    unsafe {
        if TSC_PER_US == 0 {
            // PIT channel 2, mode 0 (one-shot), ~10ms count
            const PIT_COUNT: u16 = 11932;
            // Disable speaker, enable gate
            let gate = x86_inb(0x61);
            x86_outb(0x61, (gate & 0xFD) | 0x01);
            // Channel 2, mode 0, binary, lo/hi byte
            x86_outb(0x43, 0xB0);
            x86_outb(0x42, (PIT_COUNT & 0xFF) as u8);
            x86_outb(0x42, (PIT_COUNT >> 8) as u8);
            // Reset latch by toggling gate
            let gate = x86_inb(0x61);
            x86_outb(0x61, gate & 0xFE);
            x86_outb(0x61, gate | 0x01);
            let start = x86_rdtsc();
            // Wait for OUT pin (bit 5) to go high
            while (x86_inb(0x61) & 0x20) == 0 {
                core::arch::asm!("nop");
            }
            let elapsed = x86_rdtsc() - start;
            TSC_PER_US = if elapsed / 10000 == 0 { 1 } else { elapsed / 10000 };
        }
        let end = x86_rdtsc() + TSC_PER_US * (us as u64);
        while x86_rdtsc() < end {
            core::arch::asm!("pause", options(nomem, nostack));
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn x86_inb(port: u16) -> u8 {
    let val: u8;
    unsafe { core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack)); }
    val
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn x86_outb(port: u16, val: u8) {
    unsafe { core::arch::asm!("out dx, al", in("al") val, in("dx") port, options(nomem, nostack)); }
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn x86_rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)); }
    ((hi as u64) << 32) | (lo as u64)
}

#[cfg(target_arch = "aarch64")]
fn arch_udelay(us: u32) {
    unsafe {
        let freq: u64;
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq);
        let ticks = (freq / 1_000_000) * (us as u64);
        let start: u64;
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) start);
        let end = start + ticks;
        loop {
            let now: u64;
            core::arch::asm!("mrs {}, cntpct_el0", out(reg) now);
            if now >= end { break; }
            core::arch::asm!("nop");
        }
    }
}

// ============================================================================
// Byte-order utilities
// ============================================================================

#[inline]
fn htons(h: u16) -> u16 { h.to_be() }
#[inline]
fn ntohs(n: u16) -> u16 { u16::from_be(n) }
#[inline]
fn htonl(h: u32) -> u32 { h.to_be() }
#[inline]
fn ntohl(n: u32) -> u32 { u32::from_be(n) }

// ============================================================================
// Network types
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct MacAddr {
    bytes: [u8; 6],
}

impl MacAddr {
    const ZERO: Self = MacAddr { bytes: [0; 6] };
    const BROADCAST: Self = MacAddr { bytes: [0xff; 6] };

    fn is_broadcast(&self) -> bool {
        self.bytes == [0xff; 6]
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct Ipv4Addr {
    addr: u32, // network byte order
}

impl Ipv4Addr {
    const ANY: Self = Ipv4Addr { addr: 0 };
    const BROADCAST: Self = Ipv4Addr { addr: 0xFFFFFFFF };

    fn from(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Addr {
            addr: u32::from_ne_bytes([a, b, c, d]),
        }
    }

    fn octets(&self) -> [u8; 4] {
        self.addr.to_ne_bytes()
    }
}

#[derive(Clone, Copy)]
struct NetConfig {
    ip: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    gateway: Ipv4Addr,
    dns: Ipv4Addr,
}

static mut CONFIG: NetConfig = NetConfig {
    ip: Ipv4Addr::ANY,
    subnet_mask: Ipv4Addr::ANY,
    gateway: Ipv4Addr::ANY,
    dns: Ipv4Addr::ANY,
};

/// RFC 1071 internet checksum over a byte buffer.
/// Reads 16-bit words in little-endian (matching the C++ implementation)
/// so that the returned u16 can be stored directly in packed struct fields.
fn checksum(data: *const u8, len: usize) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < len {
        let word = unsafe { (*data.add(i) as u16) | ((*data.add(i + 1) as u16) << 8) };
        sum += word as u32;
        i += 2;
    }
    if i < len {
        sum += unsafe { *data.add(i) as u32 };
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// TCP/UDP pseudo-header checksum.
/// Matches the C++ implementation: pseudo-header + data summed in LE byte order.
fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, data: *const u8, len: usize) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header — read addr fields as LE 16-bit words (matching C++ struct layout)
    sum += (src.addr & 0xFFFF) as u32;
    sum += (src.addr >> 16) as u32;
    sum += (dst.addr & 0xFFFF) as u32;
    sum += (dst.addr >> 16) as u32;
    sum += (proto as u32) << 8; // zero byte | proto byte, LE word
    sum += htons(len as u16) as u32; // length in network byte order, stored LE

    // Data — read in LE byte order
    let mut i = 0;
    while i + 1 < len {
        let word = unsafe { (*data.add(i) as u16) | ((*data.add(i + 1) as u16) << 8) };
        sum += word as u32;
        i += 2;
    }
    if i < len {
        sum += unsafe { *data.add(i) as u32 };
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ============================================================================
// Ethernet
// ============================================================================

const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV4: u16 = 0x0800;

#[repr(C, packed)]
struct EthernetHeader {
    dst: MacAddr,
    src: MacAddr,
    ethertype: u16, // network byte order
}

static mut OUR_MAC: MacAddr = MacAddr::ZERO;
static mut MAC_CACHED: bool = false;

fn ethernet_our_mac() -> MacAddr {
    unsafe {
        if !MAC_CACHED {
            drivers::driver_virtio_net_get_mac(OUR_MAC.bytes.as_mut_ptr());
            MAC_CACHED = true;
        }
        OUR_MAC
    }
}

static mut ETH_TX_BUF: [u8; 1514] = [0; 1514]; // 14 header + 1500 payload

fn ethernet_send(dst: MacAddr, ethertype: u16, payload: &[u8]) {
    unsafe {
        let hdr = &mut *(ETH_TX_BUF.as_mut_ptr() as *mut EthernetHeader);
        hdr.dst = dst;
        hdr.src = ethernet_our_mac();
        hdr.ethertype = htons(ethertype);

        let payload_len = payload.len().min(1500);
        ptr::copy_nonoverlapping(payload.as_ptr(), ETH_TX_BUF.as_mut_ptr().add(14), payload_len);

        drivers::driver_virtio_net_send(ETH_TX_BUF.as_ptr(), (14 + payload_len) as u32);
    }
}

/// Ethernet frame receive callback — dispatches to ARP or IPv4.
unsafe extern "C" fn ethernet_receive(data: *const u8, len: u32) {
    let len = len as usize;
    if len < 14 {
        return;
    }
    let hdr = unsafe { &*(data as *const EthernetHeader) };
    let ethertype = ntohs(hdr.ethertype);
    let payload = unsafe { data.add(14) };
    let payload_len = len - 14;

    match ethertype {
        ETHERTYPE_ARP => arp_receive(payload, payload_len),
        ETHERTYPE_IPV4 => ipv4_receive(payload, payload_len),
        _ => {}
    }
}

// ============================================================================
// ARP
// ============================================================================

const ARP_CACHE_SIZE: usize = 64;

#[repr(C, packed)]
struct ArpPacket {
    hw_type: u16,
    proto_type: u16,
    hw_len: u8,
    proto_len: u8,
    operation: u16,
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
}

const ARP_OP_REQUEST: u16 = 1;
const ARP_OP_REPLY: u16 = 2;

struct ArpEntry {
    ip: Ipv4Addr,
    mac: MacAddr,
    valid: bool,
}

impl ArpEntry {
    const fn new() -> Self {
        ArpEntry {
            ip: Ipv4Addr::ANY,
            mac: MacAddr::ZERO,
            valid: false,
        }
    }
}

static mut ARP_CACHE: [ArpEntry; ARP_CACHE_SIZE] = [const { ArpEntry::new() }; ARP_CACHE_SIZE];
static mut GATEWAY_MAC: MacAddr = MacAddr::ZERO;
static mut GATEWAY_MAC_VALID: bool = false;

fn arp_lookup(ip: Ipv4Addr) -> Option<MacAddr> {
    unsafe {
        for i in 0..ARP_CACHE_SIZE {
            if ARP_CACHE[i].valid && ARP_CACHE[i].ip == ip {
                return Some(ARP_CACHE[i].mac);
            }
        }
        None
    }
}

fn arp_cache_update(ip: Ipv4Addr, mac: MacAddr) {
    unsafe {
        // Check if already in cache
        for i in 0..ARP_CACHE_SIZE {
            if ARP_CACHE[i].valid && ARP_CACHE[i].ip == ip {
                ARP_CACHE[i].mac = mac;
                return;
            }
        }
        // Find empty slot
        for i in 0..ARP_CACHE_SIZE {
            if !ARP_CACHE[i].valid {
                ARP_CACHE[i] = ArpEntry { ip, mac, valid: true };
                return;
            }
        }
        // Overwrite first entry (simple LRU)
        ARP_CACHE[0] = ArpEntry { ip, mac, valid: true };
    }
}

fn arp_request(target_ip: Ipv4Addr) {
    let our_mac = ethernet_our_mac();
    let our_ip = unsafe { CONFIG.ip };

    let mut pkt = ArpPacket {
        hw_type: htons(1),
        proto_type: htons(0x0800),
        hw_len: 6,
        proto_len: 4,
        operation: htons(ARP_OP_REQUEST),
        sender_mac: our_mac,
        sender_ip: our_ip,
        target_mac: MacAddr::ZERO,
        target_ip,
    };
    let data = unsafe { core::slice::from_raw_parts(&pkt as *const _ as *const u8, 28) };
    ethernet_send(MacAddr::BROADCAST, ETHERTYPE_ARP, data);
}

fn arp_receive(data: *const u8, len: usize) {
    if len < 28 {
        return;
    }
    let pkt = unsafe { &*(data as *const ArpPacket) };
    let our_ip = unsafe { CONFIG.ip };

    // Copy fields out of packed struct before use (avoids unaligned references)
    let sender_ip = pkt.sender_ip;
    let sender_mac = pkt.sender_mac;
    let target_ip = pkt.target_ip;
    let operation = pkt.operation;

    // Update cache from any ARP packet
    if sender_ip != Ipv4Addr::ANY {
        arp_cache_update(sender_ip, sender_mac);
        // Update gateway MAC cache
        unsafe {
            if sender_ip == CONFIG.gateway {
                GATEWAY_MAC = sender_mac;
                GATEWAY_MAC_VALID = true;
            }
        }
    }

    // Reply to requests for our IP
    let op = ntohs(operation);
    if op == ARP_OP_REQUEST && target_ip == our_ip && our_ip != Ipv4Addr::ANY {
        let our_mac = ethernet_our_mac();
        let reply = ArpPacket {
            hw_type: htons(1),
            proto_type: htons(0x0800),
            hw_len: 6,
            proto_len: 4,
            operation: htons(ARP_OP_REPLY),
            sender_mac: our_mac,
            sender_ip: our_ip,
            target_mac: sender_mac,
            target_ip: sender_ip,
        };
        let data = unsafe { core::slice::from_raw_parts(&reply as *const _ as *const u8, 28) };
        ethernet_send(sender_mac, ETHERTYPE_ARP, data);
    }
}

/// Resolve an IP address to a MAC address (blocking, with retries).
fn arp_resolve(ip: Ipv4Addr) -> Option<MacAddr> {
    if ip == Ipv4Addr::BROADCAST || ip.addr == 0xFFFFFFFF {
        return Some(MacAddr::BROADCAST);
    }
    if ip == Ipv4Addr::ANY {
        return None;
    }

    // Use gateway for non-local addresses
    let target = unsafe {
        let mask = CONFIG.subnet_mask.addr;
        if (ip.addr & mask) != (CONFIG.ip.addr & mask) && CONFIG.gateway != Ipv4Addr::ANY {
            // Fast-path: cached gateway MAC
            if GATEWAY_MAC_VALID {
                return Some(GATEWAY_MAC);
            }
            CONFIG.gateway
        } else {
            ip
        }
    };

    // Check cache
    if let Some(mac) = arp_lookup(target) {
        return Some(mac);
    }

    // Send request and poll for reply
    for _retry in 0..3 {
        arp_request(target);
        for _poll in 0..200_000 {
            drivers::driver_virtio_net_poll(ethernet_receive);
            if let Some(mac) = arp_lookup(target) {
                return Some(mac);
            }
        }
    }
    None
}

fn arp_announce() {
    let our_mac = ethernet_our_mac();
    let our_ip = unsafe { CONFIG.ip };

    let pkt = ArpPacket {
        hw_type: htons(1),
        proto_type: htons(0x0800),
        hw_len: 6,
        proto_len: 4,
        operation: htons(ARP_OP_REPLY),
        sender_mac: our_mac,
        sender_ip: our_ip,
        target_mac: MacAddr::BROADCAST,
        target_ip: our_ip,
    };
    let data = unsafe { core::slice::from_raw_parts(&pkt as *const _ as *const u8, 28) };
    ethernet_send(MacAddr::BROADCAST, ETHERTYPE_ARP, data);
}

// ============================================================================
// IPv4
// ============================================================================

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

#[repr(C, packed)]
struct Ipv4Header {
    version_ihl: u8,
    tos: u8,
    total_length: u16,
    identification: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src: Ipv4Addr,
    dst: Ipv4Addr,
}

static mut IP_ID_COUNTER: u16 = 1;
static mut IPV4_TX_BUF: [u8; 1500] = [0; 1500];

fn ipv4_send(dst: Ipv4Addr, proto: u8, payload: &[u8]) {
    let payload_len = payload.len().min(1480);
    let total_len = 20 + payload_len;

    unsafe {
        let hdr = &mut *(IPV4_TX_BUF.as_mut_ptr() as *mut Ipv4Header);
        hdr.version_ihl = 0x45; // IPv4, IHL=5 (20 bytes)
        hdr.tos = 0;
        hdr.total_length = htons(total_len as u16);
        hdr.identification = htons(IP_ID_COUNTER);
        IP_ID_COUNTER = IP_ID_COUNTER.wrapping_add(1);
        hdr.flags_fragment = htons(0x4000); // Don't Fragment
        hdr.ttl = 64;
        hdr.protocol = proto;
        hdr.checksum = 0;
        hdr.src = CONFIG.ip;
        hdr.dst = dst;

        // Header checksum
        hdr.checksum = checksum(IPV4_TX_BUF.as_ptr(), 20);

        // Copy payload
        ptr::copy_nonoverlapping(payload.as_ptr(), IPV4_TX_BUF.as_mut_ptr().add(20), payload_len);
    }

    // Resolve destination MAC
    let dst_mac = if unsafe { CONFIG.ip } == Ipv4Addr::ANY {
        // Pre-DHCP: send as broadcast
        MacAddr::BROADCAST
    } else {
        match arp_resolve(dst) {
            Some(mac) => mac,
            None => return, // Can't resolve — drop packet
        }
    };

    unsafe {
        ethernet_send(dst_mac, ETHERTYPE_IPV4, &IPV4_TX_BUF[..total_len]);
    }
}

fn ipv4_receive(data: *const u8, len: usize) {
    if len < 20 {
        return;
    }
    let hdr = unsafe { &*(data as *const Ipv4Header) };

    // Validate
    let version = hdr.version_ihl >> 4;
    if version != 4 {
        return;
    }
    let ihl = (hdr.version_ihl & 0x0F) as usize;
    if ihl < 5 {
        return;
    }
    let header_len = ihl * 4;
    let total_len = ntohs(hdr.total_length) as usize;
    if total_len > len || total_len < header_len {
        return;
    }

    // Check destination
    let our_ip = unsafe { CONFIG.ip };
    let dst = hdr.dst;
    if dst != our_ip && dst != Ipv4Addr::BROADCAST && our_ip != Ipv4Addr::ANY {
        // Check subnet broadcast
        let mask = unsafe { CONFIG.subnet_mask.addr };
        if mask != 0 && (dst.addr & !mask) != !mask {
            return;
        }
    }

    let payload = unsafe { data.add(header_len) };
    let payload_len = total_len - header_len;

    match hdr.protocol {
        PROTO_TCP => tcp_receive(hdr.src, hdr.dst, payload, payload_len),
        _ => {}
    }
}

// ============================================================================
// TCP
// ============================================================================

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
            kernel_mm::mm_kfree(CONNECTIONS[idx].rx_buf);
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

fn tcp_receive(src_ip: Ipv4Addr, _dst_ip: Ipv4Addr, data: *const u8, len: usize) {
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
            c.rx_buf = kernel_mm::mm_kmalloc(RX_BUF_SIZE);
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
// DHCP
// ============================================================================

#[repr(C, packed)]
struct UdpHeader {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
}

#[repr(C, packed)]
struct DhcpPacket {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    siaddr: Ipv4Addr,
    giaddr: Ipv4Addr,
    chaddr: [u8; 16],
    sname: [u8; 64],
    file: [u8; 128],
    magic_cookie: u32,
}

const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;
const DHCP_NAK: u8 = 6;

static mut DHCP_XID: u32 = 0x12345678;
static mut DHCP_GOT_OFFER: bool = false;
static mut DHCP_GOT_ACK: bool = false;
static mut DHCP_OFFERED_IP: Ipv4Addr = Ipv4Addr::ANY;
static mut DHCP_OFFERED_SUBNET: Ipv4Addr = Ipv4Addr::ANY;
static mut DHCP_OFFERED_GATEWAY: Ipv4Addr = Ipv4Addr::ANY;
static mut DHCP_OFFERED_DNS: Ipv4Addr = Ipv4Addr::ANY;
static mut DHCP_SERVER_IP: Ipv4Addr = Ipv4Addr::ANY;

/// DHCP receive callback — processes raw ethernet frames during DHCP.
unsafe extern "C" fn dhcp_receive(data: *const u8, len: u32) {
    let len = len as usize;
    if len < 14 {
        return;
    }
    let hdr = unsafe { &*(data as *const EthernetHeader) };
    let ethertype = ntohs(hdr.ethertype);

    // Also process ARP during DHCP
    if ethertype == ETHERTYPE_ARP && len >= 14 + 28 {
        arp_receive(unsafe { data.add(14) }, len - 14);
        return;
    }

    if ethertype != ETHERTYPE_IPV4 || len < 14 + 20 {
        return;
    }
    let ip_hdr = unsafe { &*(data.add(14) as *const Ipv4Header) };
    if ip_hdr.protocol != PROTO_UDP {
        return;
    }
    let ip_hdr_len = ((ip_hdr.version_ihl & 0x0F) as usize) * 4;
    if len < 14 + ip_hdr_len + 8 {
        return;
    }

    let udp = unsafe { &*(data.add(14 + ip_hdr_len) as *const UdpHeader) };
    if ntohs(udp.dst_port) != 68 || ntohs(udp.src_port) != 67 {
        return;
    }

    let dhcp_offset = 14 + ip_hdr_len + 8;
    if len < dhcp_offset + 240 {
        return;
    }

    let dhcp = unsafe { &*(data.add(dhcp_offset) as *const DhcpPacket) };
    if dhcp.xid != unsafe { DHCP_XID } || dhcp.magic_cookie != htonl(0x63825363) {
        return;
    }

    // Parse options
    let opts_start = dhcp_offset + 240;
    let opts_data = unsafe { core::slice::from_raw_parts(data.add(opts_start), len - opts_start) };

    let mut msg_type: u8 = 0;
    let mut subnet = Ipv4Addr::ANY;
    let mut gateway = Ipv4Addr::ANY;
    let mut dns = Ipv4Addr::ANY;
    let mut server_id = Ipv4Addr::ANY;

    let mut i = 0;
    while i < opts_data.len() {
        let opt = opts_data[i];
        if opt == 255 { break; } // End
        if opt == 0 { i += 1; continue; } // Pad
        if i + 1 >= opts_data.len() { break; }
        let opt_len = opts_data[i + 1] as usize;
        if i + 2 + opt_len > opts_data.len() { break; }
        let val = &opts_data[i + 2..i + 2 + opt_len];

        match opt {
            1 if val.len() >= 4 => subnet = Ipv4Addr::from(val[0], val[1], val[2], val[3]),
            3 if val.len() >= 4 => gateway = Ipv4Addr::from(val[0], val[1], val[2], val[3]),
            6 if val.len() >= 4 => dns = Ipv4Addr::from(val[0], val[1], val[2], val[3]),
            53 if val.len() >= 1 => msg_type = val[0],
            54 if val.len() >= 4 => server_id = Ipv4Addr::from(val[0], val[1], val[2], val[3]),
            _ => {}
        }

        i += 2 + opt_len;
    }

    unsafe {
        match msg_type {
            DHCP_OFFER => {
                DHCP_OFFERED_IP = dhcp.yiaddr;
                DHCP_OFFERED_SUBNET = subnet;
                DHCP_OFFERED_GATEWAY = gateway;
                DHCP_OFFERED_DNS = dns;
                DHCP_SERVER_IP = server_id;
                DHCP_GOT_OFFER = true;
            }
            DHCP_ACK => {
                DHCP_OFFERED_IP = dhcp.yiaddr;
                if subnet != Ipv4Addr::ANY { DHCP_OFFERED_SUBNET = subnet; }
                if gateway != Ipv4Addr::ANY { DHCP_OFFERED_GATEWAY = gateway; }
                if dns != Ipv4Addr::ANY { DHCP_OFFERED_DNS = dns; }
                DHCP_GOT_ACK = true;
            }
            DHCP_NAK => {
                DHCP_GOT_OFFER = false;
            }
            _ => {}
        }
    }
}

fn build_dhcp_base() -> DhcpPacket {
    let mac = ethernet_our_mac();
    let mut pkt: DhcpPacket = unsafe { core::mem::zeroed() };
    pkt.op = 1; // BOOTREQUEST
    pkt.htype = 1; // Ethernet
    pkt.hlen = 6;
    pkt.xid = unsafe { DHCP_XID };
    pkt.flags = htons(0x8000); // Broadcast
    pkt.magic_cookie = htonl(0x63825363);
    pkt.chaddr[..6].copy_from_slice(&mac.bytes);
    pkt
}

fn dhcp_send_discover() {
    // Build Ethernet + IP + UDP + DHCP frame
    let mut frame = [0u8; 590]; // 14 eth + 20 ip + 8 udp + dhcp
    let our_mac = ethernet_our_mac();

    // Ethernet header
    let eth = unsafe { &mut *(frame.as_mut_ptr() as *mut EthernetHeader) };
    eth.dst = MacAddr::BROADCAST;
    eth.src = our_mac;
    eth.ethertype = htons(ETHERTYPE_IPV4);

    // DHCP packet
    let dhcp_base = build_dhcp_base();
    let dhcp_offset = 14 + 20 + 8;
    unsafe {
        ptr::copy_nonoverlapping(
            &dhcp_base as *const _ as *const u8,
            frame.as_mut_ptr().add(dhcp_offset),
            240,
        );
    }

    // DHCP options
    let mut opt_pos = dhcp_offset + 240;
    frame[opt_pos] = 53; frame[opt_pos + 1] = 1; frame[opt_pos + 2] = DHCP_DISCOVER; opt_pos += 3;
    // Parameter request list
    frame[opt_pos] = 55; frame[opt_pos + 1] = 3; frame[opt_pos + 2] = 1; frame[opt_pos + 3] = 3; frame[opt_pos + 4] = 6; opt_pos += 5;
    frame[opt_pos] = 255; opt_pos += 1;

    // Pad DHCP payload to minimum 300 bytes (RFC 2131 / BOOTP minimum)
    let min_dhcp_end = dhcp_offset + 300;
    if opt_pos < min_dhcp_end {
        opt_pos = min_dhcp_end;
    }

    let dhcp_len = opt_pos - dhcp_offset;
    let udp_len = 8 + dhcp_len;
    let ip_total = 20 + udp_len;

    // UDP header
    let udp = unsafe { &mut *(frame.as_mut_ptr().add(14 + 20) as *mut UdpHeader) };
    udp.src_port = htons(68);
    udp.dst_port = htons(67);
    udp.length = htons(udp_len as u16);
    udp.checksum = 0;

    // IP header
    let ip = unsafe { &mut *(frame.as_mut_ptr().add(14) as *mut Ipv4Header) };
    ip.version_ihl = 0x45;
    ip.total_length = htons(ip_total as u16);
    ip.ttl = 64;
    ip.protocol = PROTO_UDP;
    ip.src = Ipv4Addr::ANY;
    ip.dst = Ipv4Addr::BROADCAST;
    ip.checksum = 0;
    ip.checksum = unsafe { checksum(frame.as_ptr().add(14) as *const u8, 20) };

    drivers::driver_virtio_net_send(frame.as_ptr(), (14 + ip_total) as u32);
}

fn dhcp_send_request() {
    let mut frame = [0u8; 590];
    let our_mac = ethernet_our_mac();

    let eth = unsafe { &mut *(frame.as_mut_ptr() as *mut EthernetHeader) };
    eth.dst = MacAddr::BROADCAST;
    eth.src = our_mac;
    eth.ethertype = htons(ETHERTYPE_IPV4);

    let dhcp_base = build_dhcp_base();
    let dhcp_offset = 14 + 20 + 8;
    unsafe {
        ptr::copy_nonoverlapping(
            &dhcp_base as *const _ as *const u8,
            frame.as_mut_ptr().add(dhcp_offset),
            240,
        );
    }

    let offered_ip = unsafe { DHCP_OFFERED_IP };
    let server_ip = unsafe { DHCP_SERVER_IP };

    // DHCP options
    let mut opt_pos = dhcp_offset + 240;
    frame[opt_pos] = 53; frame[opt_pos + 1] = 1; frame[opt_pos + 2] = DHCP_REQUEST; opt_pos += 3;
    // Requested IP
    let ip_bytes = offered_ip.octets();
    frame[opt_pos] = 50; frame[opt_pos + 1] = 4;
    frame[opt_pos + 2..opt_pos + 6].copy_from_slice(&ip_bytes);
    opt_pos += 6;
    // Server ID
    let srv_bytes = server_ip.octets();
    frame[opt_pos] = 54; frame[opt_pos + 1] = 4;
    frame[opt_pos + 2..opt_pos + 6].copy_from_slice(&srv_bytes);
    opt_pos += 6;
    // Parameter request list
    frame[opt_pos] = 55; frame[opt_pos + 1] = 3; frame[opt_pos + 2] = 1; frame[opt_pos + 3] = 3; frame[opt_pos + 4] = 6; opt_pos += 5;
    frame[opt_pos] = 255; opt_pos += 1;

    // Pad DHCP payload to minimum 300 bytes (RFC 2131 / BOOTP minimum)
    let min_dhcp_end = dhcp_offset + 300;
    if opt_pos < min_dhcp_end {
        opt_pos = min_dhcp_end;
    }

    let dhcp_len = opt_pos - dhcp_offset;
    let udp_len = 8 + dhcp_len;
    let ip_total = 20 + udp_len;

    let udp = unsafe { &mut *(frame.as_mut_ptr().add(14 + 20) as *mut UdpHeader) };
    udp.src_port = htons(68);
    udp.dst_port = htons(67);
    udp.length = htons(udp_len as u16);
    udp.checksum = 0;

    let ip = unsafe { &mut *(frame.as_mut_ptr().add(14) as *mut Ipv4Header) };
    ip.version_ihl = 0x45;
    ip.total_length = htons(ip_total as u16);
    ip.ttl = 64;
    ip.protocol = PROTO_UDP;
    ip.src = Ipv4Addr::ANY;
    ip.dst = Ipv4Addr::BROADCAST;
    ip.checksum = 0;
    ip.checksum = unsafe { checksum(frame.as_ptr().add(14) as *const u8, 20) };

    drivers::driver_virtio_net_send(frame.as_ptr(), (14 + ip_total) as u32);
}

fn dhcp_poll_wait(timeout_ms: u32) -> bool {
    for _ in 0..timeout_ms {
        unsafe {
            drivers::driver_virtio_net_poll(dhcp_receive);
            if DHCP_GOT_OFFER || DHCP_GOT_ACK {
                return true;
            }
            arch_udelay(1000); // 1ms
        }
    }
    false
}

// ============================================================================
// Extern "C" API — called by C++ (kernel/entry.cc and uni/ffi.cc)
// ============================================================================

/// Initialize TCP connection pool.
#[unsafe(no_mangle)]
pub extern "C" fn net_tcp_init() {
    unsafe {
        for i in 0..MAX_CONNECTIONS {
            CONNECTIONS[i] = TcpConnection::new();
        }
    }
}

/// DHCP discover — blocks until IP obtained or timeout.
#[unsafe(no_mangle)]
pub extern "C" fn net_dhcp_discover() -> bool {
    unsafe {
        DHCP_GOT_OFFER = false;
        DHCP_GOT_ACK = false;
        DHCP_XID = DHCP_XID.wrapping_add(1);
    }

    // Phase 1: DISCOVER → OFFER
    for _attempt in 0..5 {
        dhcp_send_discover();
        if dhcp_poll_wait(2000) && unsafe { DHCP_GOT_OFFER } {
            break;
        }
    }
    if !unsafe { DHCP_GOT_OFFER } {
        return false;
    }

    // Phase 2: REQUEST → ACK
    unsafe { DHCP_GOT_ACK = false; }
    for _attempt in 0..5 {
        dhcp_send_request();
        if dhcp_poll_wait(2000) && unsafe { DHCP_GOT_ACK } {
            break;
        }
    }
    if !unsafe { DHCP_GOT_ACK } {
        return false;
    }

    // Apply configuration
    unsafe {
        CONFIG.ip = DHCP_OFFERED_IP;
        CONFIG.subnet_mask = DHCP_OFFERED_SUBNET;
        CONFIG.gateway = DHCP_OFFERED_GATEWAY;
        CONFIG.dns = DHCP_OFFERED_DNS;
    }

    // Gratuitous ARP
    arp_announce();

    true
}

/// Set fallback network config (called by entry.cc if DHCP fails).
#[unsafe(no_mangle)]
pub extern "C" fn net_set_fallback_config(
    ip_a: u8, ip_b: u8, ip_c: u8, ip_d: u8,
    mask_a: u8, mask_b: u8, mask_c: u8, mask_d: u8,
    gw_a: u8, gw_b: u8, gw_c: u8, gw_d: u8,
    dns_a: u8, dns_b: u8, dns_c: u8, dns_d: u8,
) {
    unsafe {
        CONFIG.ip = Ipv4Addr::from(ip_a, ip_b, ip_c, ip_d);
        CONFIG.subnet_mask = Ipv4Addr::from(mask_a, mask_b, mask_c, mask_d);
        CONFIG.gateway = Ipv4Addr::from(gw_a, gw_b, gw_c, gw_d);
        CONFIG.dns = Ipv4Addr::from(dns_a, dns_b, dns_c, dns_d);
    }
}

// ---- TCP extern "C" API (replaces uni/ffi.cc TCP wrappers) ------------------

#[unsafe(no_mangle)]
pub extern "C" fn uni_tcp_listen(port: u16) -> *mut () {
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

#[unsafe(no_mangle)]
pub extern "C" fn uni_tcp_accept(conn: *mut ()) -> *mut () {
    let listener_idx = (conn as usize) - 1;
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

#[unsafe(no_mangle)]
pub extern "C" fn uni_tcp_has_data(conn: *mut ()) -> bool {
    let idx = (conn as usize) - 1;
    if idx >= MAX_CONNECTIONS {
        return false;
    }
    unsafe { CONNECTIONS[idx].rx_used() > 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn uni_tcp_recv(conn: *mut (), buf: *mut u8, max_len: usize) -> usize {
    let idx = (conn as usize) - 1;
    if idx >= MAX_CONNECTIONS {
        return 0;
    }
    unsafe {
        let out = core::slice::from_raw_parts_mut(buf, max_len);
        CONNECTIONS[idx].rx_pop(out)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn uni_tcp_send(conn: *mut (), data: *const u8, len: usize) -> i32 {
    let idx = (conn as usize) - 1;
    if idx >= MAX_CONNECTIONS {
        return -1;
    }
    unsafe {
        let c = &mut CONNECTIONS[idx];
        if c.state != TcpState::Established {
            return -1;
        }
        let payload = core::slice::from_raw_parts(data, len);

        // Send in MSS-sized chunks
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
                &payload[sent..sent + chunk],
            );
            c.snd_nxt = c.snd_nxt.wrapping_add(chunk as u32);
            sent += chunk;
        }
        sent as i32
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn uni_tcp_close(conn: *mut ()) {
    let idx = (conn as usize) - 1;
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

#[unsafe(no_mangle)]
pub extern "C" fn uni_tcp_is_closed(conn: *mut ()) -> bool {
    let idx = (conn as usize) - 1;
    if idx >= MAX_CONNECTIONS {
        return true;
    }
    unsafe { CONNECTIONS[idx].state == TcpState::Closed }
}

#[unsafe(no_mangle)]
pub extern "C" fn uni_tcp_poll() {
    drivers::driver_virtio_net_poll(ethernet_receive);
}
