// net/lib.rs — Network stack umbrella crate.
//
// Re-exports per-protocol sub-crates and provides full-stack
// poll/dispatch that ties them together.
//
// Tier 2 (single-queue): core 0 polls VirtIO, classifies frames
// by flow hash, and distributes to per-core RX inboxes. APs drain
// their inbox and process packets. TX from APs goes through staging
// buffers that core 0 flushes.

#![no_std]
#![allow(static_mut_refs)]

extern crate drivers;
extern crate kernel;
pub extern crate net_types as types;
pub extern crate net_ethernet as ethernet;
pub extern crate net_arp as arp;
pub extern crate net_ipv4 as ipv4;
pub extern crate net_tcp as tcp;
pub extern crate net_udp as udp;
pub extern crate net_dhcp as dhcp;

use kernel::percpu;

/// Whether multi-core distribution has been initialized.
static mut MULTICORE_INIT: bool = false;

/// Wakeup flags — set during distribution, cleared each poll cycle.
static mut WAKEUP: [bool; percpu::MAX_CORES] = [false; percpu::MAX_CORES];

/// RX poll lock: 0 = free, 1 = held. Any core can try to acquire.
static RX_LOCK: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Poll the network device and dispatch received frames through the
/// full stack: Ethernet -> ARP/IPv4 -> TCP/UDP.
///
/// In single-core mode, all processing happens here.
/// In Tier 2 multi-core mode, any idle core can become the distributor
/// by acquiring the RX lock. This avoids dedicating a core to distribution.
pub fn poll() {
    let num_cores = percpu::num_cores();

    if num_cores <= 1 {
        // Single-core: existing path, no distribution overhead.
        drivers::virtio_net::poll(net_receive);
        return;
    }

    // Tier 2: multi-core with software distribution.
    unsafe {
        if !MULTICORE_INIT {
            MULTICORE_INIT = true;
            kernel::serial::puts(b"[net] Tier 2: software distribution (");
            let mut buf = [0u8; 4];
            let len = fmt_u32(&mut buf, num_cores);
            kernel::serial::puts(&buf[..len]);
            kernel::serial::puts(b" cores)\n");
        }
    }

    // Try to become the distributor. Non-blocking: if another core holds
    // the lock, skip distribution and just process our own connections.
    let got_lock = RX_LOCK.compare_exchange(
        0, 1,
        core::sync::atomic::Ordering::Acquire,
        core::sync::atomic::Ordering::Relaxed,
    ).is_ok();

    if got_lock {
        // We're the distributor this cycle.
        // Flush TX staging first — responses from previous cycle.
        drivers::virtio_net::flush_tx_staging();

        unsafe {
            for i in 0..num_cores as usize {
                WAKEUP[i] = false;
            }
        }

        // Poll VirtIO and distribute frames.
        drivers::virtio_net::poll(distribute_frame);

        // Wake cores that received new packets.
        unsafe {
            let any_wakeup = (1..num_cores as usize).any(|i| WAKEUP[i]);
            if any_wakeup {
                kernel::wake_cores();
            }
        }

        // Flush again (APs may have responded during distribution).
        drivers::virtio_net::flush_tx_staging();

        RX_LOCK.store(0, core::sync::atomic::Ordering::Release);
    }
}

/// Classify a frame and distribute it to the appropriate core.
/// Called as the VirtIO poll callback on core 0.
fn distribute_frame(frame: &[u8]) {
    let num_cores = percpu::num_cores();

    // Parse enough of the frame to classify by protocol and flow.
    if let Some((ethertype, payload)) = ethernet::ethernet_parse(frame) {
        match ethertype {
            ethernet::ETHERTYPE_ARP => {
                // ARP: always core 0 (modifies shared ARP cache).
                arp::arp_receive(payload);
            }
            ethernet::ETHERTYPE_IPV4 => {
                if let Some(pkt) = ipv4::ipv4_receive(payload) {
                    // Extract ports for flow hash (TCP and UDP both have ports at offset 0-3).
                    let (src_port, dst_port) = if pkt.payload.len() >= 4 {
                        (u16::from_be_bytes([pkt.payload[0], pkt.payload[1]]),
                         u16::from_be_bytes([pkt.payload[2], pkt.payload[3]]))
                    } else {
                        (0, 0)
                    };
                    let target = flow_hash(
                        pkt.src.addr, pkt.dst.addr, src_port, dst_port, num_cores,
                    );

                    let my_core = kernel::cpu_id();
                    if target == my_core {
                        // Target is the current core — process inline (no inbox).
                        match pkt.protocol {
                            ipv4::PROTO_TCP => tcp::tcp_receive(pkt.src, pkt.dst, pkt.payload),
                            ipv4::PROTO_UDP => udp::udp_receive(pkt.src, pkt.dst, pkt.payload),
                            _ => {}
                        }
                    } else if num_cores <= 1 {
                        // Single-core fallback.
                        match pkt.protocol {
                            ipv4::PROTO_TCP => tcp::tcp_receive(pkt.src, pkt.dst, pkt.payload),
                            ipv4::PROTO_UDP => udp::udp_receive(pkt.src, pkt.dst, pkt.payload),
                            _ => {}
                        }
                    } else {
                        // Distribute to target core's RX inbox.
                        unsafe {
                            let core = percpu::get(target);
                            if core.rx_inbox.push(frame) {
                                WAKEUP[target as usize] = true;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Process a single received frame through the full stack.
/// Called on core 0 for single-core mode and ARP/TCP frames,
/// and on any core for distributed frames via ap_poll.
pub fn net_receive(frame: &[u8]) {
    if let Some((ethertype, payload)) = ethernet::ethernet_parse(frame) {
        match ethertype {
            ethernet::ETHERTYPE_ARP => arp::arp_receive(payload),
            ethernet::ETHERTYPE_IPV4 => {
                if let Some(pkt) = ipv4::ipv4_receive(payload) {
                    match pkt.protocol {
                        ipv4::PROTO_TCP => tcp::tcp_receive(pkt.src, pkt.dst, pkt.payload),
                        ipv4::PROTO_UDP => udp::udp_receive(pkt.src, pkt.dst, pkt.payload),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

/// Flow hash: map a 4-tuple to a core index.
/// In Tier 2, core 0 is the dedicated distributor — it shouldn't also
/// handle application connections. Hash to cores 1..N only (when multi-core).
fn flow_hash(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, num_cores: u32) -> u32 {
    let mut h: u32 = 2166136261; // FNV offset basis
    h ^= src_ip;
    h = h.wrapping_mul(16777619);
    h ^= dst_ip;
    h = h.wrapping_mul(16777619);
    h ^= src_port as u32;
    h = h.wrapping_mul(16777619);
    h ^= dst_port as u32;
    h = h.wrapping_mul(16777619);
    h % num_cores
}

fn fmt_u32(buf: &mut [u8], mut val: u32) -> usize {
    if val == 0 { buf[0] = b'0'; return 1; }
    let mut tmp = [0u8; 10];
    let mut len = 0;
    while val > 0 { tmp[len] = b'0' + (val % 10) as u8; val /= 10; len += 1; }
    for i in 0..len { buf[i] = tmp[len - 1 - i]; }
    len
}
