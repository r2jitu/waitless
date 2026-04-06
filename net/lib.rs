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

/// Poll the network device and dispatch received frames through the
/// full stack: Ethernet -> ARP/IPv4 -> TCP/UDP.
///
/// In single-core mode, all processing happens here.
/// In Tier 2 multi-core mode, core 0 distributes frames to per-core
/// inboxes and flushes TX staging from other cores.
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
            percpu::set_ap_poll_fn(ap_poll);
            MULTICORE_INIT = true;
            kernel::serial::puts(b"[net] Tier 2: software distribution (");
            let mut buf = [0u8; 4];
            let len = fmt_u32(&mut buf, num_cores);
            kernel::serial::puts(&buf[..len]);
            kernel::serial::puts(b" cores)\n");
        }

        // Clear wakeup flags.
        for i in 0..percpu::MAX_CORES {
            WAKEUP[i] = false;
        }
    }

    // Core 0: poll VirtIO and distribute frames.
    drivers::virtio_net::poll(distribute_frame);

    // Batched IPI: one per core that received new packets.
    unsafe {
        for i in 1..num_cores as usize {
            if WAKEUP[i] {
                kernel::send_ipi(i as u32);
            }
        }
    }

    // Flush TX staging from all other cores.
    drivers::virtio_net::flush_tx_staging();
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
                    match pkt.protocol {
                        ipv4::PROTO_TCP => {
                            // TCP: always core 0 (global connection table, not yet per-core).
                            tcp::tcp_receive(pkt.src, pkt.dst, pkt.payload);
                        }
                        ipv4::PROTO_UDP => {
                            // UDP: distribute by flow hash (stateless, safe on any core).
                            let (src_port, dst_port) = udp_ports(pkt.payload);
                            let target = flow_hash(
                                pkt.src.addr, pkt.dst.addr, src_port, dst_port, num_cores,
                            );
                            if target == 0 {
                                udp::udp_receive(pkt.src, pkt.dst, pkt.payload);
                            } else {
                                // Copy the raw frame to the target core's RX inbox.
                                unsafe {
                                    let core = percpu::get(target);
                                    if core.rx_inbox.push(frame) {
                                        WAKEUP[target as usize] = true;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

/// AP poll function: drain this core's RX inbox and process each frame.
/// Returns true if any work was done.
fn ap_poll(core_id: u32) -> bool {
    let mut did_work = false;
    unsafe {
        let core = percpu::get(core_id);
        while let Some(frame) = core.rx_inbox.pop() {
            net_receive(frame);
            did_work = true;
        }
    }
    did_work
}

/// Process a single received frame through the full stack.
/// Called on core 0 for single-core mode and ARP/TCP frames,
/// and on any core for distributed UDP frames.
fn net_receive(frame: &[u8]) {
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

/// Extract UDP source and destination ports from a UDP header.
fn udp_ports(payload: &[u8]) -> (u16, u16) {
    if payload.len() < 4 {
        return (0, 0);
    }
    let src = u16::from_be_bytes([payload[0], payload[1]]);
    let dst = u16::from_be_bytes([payload[2], payload[3]]);
    (src, dst)
}

/// Flow hash: map a 4-tuple to a core index.
/// Uses FNV-1a-inspired multiplicative hashing for good distribution.
fn flow_hash(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, num_cores: u32) -> u32 {
    let mut h: u32 = 2166136261; // FNV offset basis
    h ^= src_ip;
    h = h.wrapping_mul(16777619); // FNV prime
    h ^= dst_ip;
    h = h.wrapping_mul(16777619);
    h ^= (src_port as u32) << 16 | dst_port as u32;
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
