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
static MULTICORE_INIT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Wakeup flags — set during distribution, cleared each poll cycle. The
/// distributor is single-threaded (only the lock holder writes), but
/// every core wakes up afterwards and reads the flags, so atomic load/
/// store removes the language-level data race.
static WAKEUP: [core::sync::atomic::AtomicBool; percpu::MAX_CORES] =
    [const { core::sync::atomic::AtomicBool::new(false) }; percpu::MAX_CORES];

/// RX poll lock: 0 = free, 1 = held. Uses load/store (not CAS) because
/// VZ.framework rejects all atomic RMW on guest RAM. The lock is best-effort:
/// two cores may both see 0 and enter, but the VirtIO RX queue is drained
/// quickly so the race window is tiny and the worst case is a redundant poll.
static RX_LOCK: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Diagnostic counters. Atomic (Relaxed) on QEMU/KVM; volatile RMW on
/// vz_compat where atomic RMW faults — best-effort either way.
#[cfg(not(vz_compat))]
static RX_LOCK_GOT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(not(vz_compat))]
static RX_LOCK_MISS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(not(vz_compat))]
static FRAMES_DISTRIBUTED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(vz_compat)]
static mut RX_LOCK_GOT: u64 = 0;
#[cfg(vz_compat)]
static mut RX_LOCK_MISS: u64 = 0;
#[cfg(vz_compat)]
static mut FRAMES_DISTRIBUTED: u64 = 0;


/// Poll the network device and dispatch received frames through the
/// full stack: Ethernet -> ARP/IPv4 -> TCP/UDP.
///
/// In single-core mode, all processing happens here.
/// In Tier 2 multi-core mode, any idle core can become the distributor
/// by acquiring the RX lock. This avoids dedicating a core to distribution.
/// Returns true if any network work was done.
pub fn poll() -> bool {
    let num_cores = percpu::num_cores();

    if num_cores <= 1 {
        return drivers::virtio_net::poll(net_receive) > 0;
    }

    // Tier 2: multi-core with software distribution.
    // On VZ, only core 0 reaches here (net_poll_cb blocks other cores).
    // poll_tier2 uses load/store for RX_LOCK under vz_compat.
    poll_tier2(num_cores)
}

fn poll_tier2(num_cores: u32) -> bool {
    if !MULTICORE_INIT.load(core::sync::atomic::Ordering::Relaxed) {
        MULTICORE_INIT.store(true, core::sync::atomic::Ordering::Relaxed);
        kernel::serial::puts(b"[net] Tier 2: software distribution (");
        let mut buf = [0u8; 4];
        let len = fmt_u32(&mut buf, num_cores);
        kernel::serial::puts(&buf[..len]);
        kernel::serial::puts(b" cores)\n");
    }

    // Try to become the distributor.
    let got_lock = if cfg!(vz_compat) {
        // VZ: load/store — VZ does not virtualize the exclusive monitor
        // (both LDXR/STXR and LSE CAS → DFSC 0x35). On VZ, net_poll_cb
        // only allows core 0 to poll, so contention is impossible; this
        // is never racy in practice.
        if RX_LOCK.load(core::sync::atomic::Ordering::Acquire) != 0 { false }
        else { RX_LOCK.store(1, core::sync::atomic::Ordering::Release); true }
    } else {
        // QEMU/KVM: proper CAS (safe under true parallelism).
        RX_LOCK.compare_exchange(0, 1,
            core::sync::atomic::Ordering::Acquire,
            core::sync::atomic::Ordering::Relaxed).is_ok()
    };
    if !got_lock {
        #[cfg(not(vz_compat))]
        { RX_LOCK_MISS.fetch_add(1, core::sync::atomic::Ordering::Relaxed); }
        #[cfg(vz_compat)]
        unsafe {
            let v = core::ptr::read_volatile(&raw const RX_LOCK_MISS);
            core::ptr::write_volatile(&raw mut RX_LOCK_MISS, v.wrapping_add(1));
        }
        return false;
    }
    #[cfg(not(vz_compat))]
    { RX_LOCK_GOT.fetch_add(1, core::sync::atomic::Ordering::Relaxed); }
    #[cfg(vz_compat)]
    unsafe {
        let v = core::ptr::read_volatile(&raw const RX_LOCK_GOT);
        core::ptr::write_volatile(&raw mut RX_LOCK_GOT, v.wrapping_add(1));
    }

    // Flush TX staging first — responses from previous cycle.
    drivers::virtio_net::flush_tx_staging();

    // Poll VirtIO RX and distribute directly (no batch buffer copy).
    for i in 0..num_cores as usize {
        WAKEUP[i].store(false, core::sync::atomic::Ordering::Relaxed);
    }

    let count = drivers::virtio_net::poll(distribute_frame);

    // Release lock.
    RX_LOCK.store(0, core::sync::atomic::Ordering::Release);

    let had_frames = count > 0;
    if had_frames {
        #[cfg(not(vz_compat))]
        { FRAMES_DISTRIBUTED.fetch_add(count as u64, core::sync::atomic::Ordering::Relaxed); }
        #[cfg(vz_compat)]
        unsafe {
            let v = core::ptr::read_volatile(&raw const FRAMES_DISTRIBUTED);
            core::ptr::write_volatile(&raw mut FRAMES_DISTRIBUTED, v.wrapping_add(count as u64));
        }
        let any_wakeup = (1..num_cores as usize)
            .any(|i| WAKEUP[i].load(core::sync::atomic::Ordering::Relaxed));
        if any_wakeup {
            kernel::wake_cores();
        }
    }

    // Flush TX (APs may have responded during distribution).
    drivers::virtio_net::flush_tx_staging();

    had_frames
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
                        // SAFETY: percpu::init() runs before any AP starts;
                        // target is bounded by num_cores. The inbox uses
                        // SPSC discipline (single producer = the distributor
                        // here, single consumer = the target core's
                        // net_drain_cb).
                        let core = unsafe { percpu::get(target) };
                        if core.rx_inbox.push(frame) {
                            WAKEUP[target as usize].store(
                                true,
                                core::sync::atomic::Ordering::Relaxed,
                            );
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

// ============================================================================
// Event loop integration
// ============================================================================

/// Register network callbacks with the kernel event loop.
/// Called during boot after virtio-net is initialized.
pub fn init_eventloop() {
    kernel::eventloop::set_net_poll(net_poll_cb);
    kernel::eventloop::set_net_drain(net_drain_cb);
    kernel::eventloop::set_net_flush(net_flush_cb);
}

fn net_poll_cb(core_id: u32) -> bool {
    // VZ: only core 0 polls VirtIO (serializes queue access without CAS).
    // Core 0 distributes to AP inboxes; APs only drain their inbox.
    // QEMU: any core can be the rotating distributor.
    if cfg!(vz_compat) && core_id != 0 {
        return false;
    }
    if RX_LOCK.load(core::sync::atomic::Ordering::Relaxed) != 0 {
        return false;
    }
    poll()
}

fn net_drain_cb(core_id: u32) -> bool {
    // SAFETY: the kernel event loop only calls this callback with the
    // current core's id; we threaded that id through, so it matches
    // `cpu_id()` at this exact moment without needing a second TLS read.
    let cc = unsafe { percpu::CurrentCore::from_id_unchecked(core_id) };
    let core = cc.percore(); // SAFE access via the token
    let mut did_work = false;
    let mut buf = [0u8; 1514];
    while let Some(len) = core.rx_inbox.pop_into(&mut buf) {
        net_receive(&buf[..len]);
        did_work = true;
    }
    did_work
}

fn net_flush_cb() {
    drivers::virtio_net::flush_tx_staging();
}

fn fmt_u32(buf: &mut [u8], mut val: u32) -> usize {
    if val == 0 { buf[0] = b'0'; return 1; }
    let mut tmp = [0u8; 10];
    let mut len = 0;
    while val > 0 { tmp[len] = b'0' + (val % 10) as u8; val /= 10; len += 1; }
    for i in 0..len { buf[i] = tmp[len - 1 - i]; }
    len
}
