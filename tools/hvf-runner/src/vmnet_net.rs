// tools/hvf-runner/src/vmnet_net.rs
//
// vmnet.framework integration via the `vmnet` crate.
//
// Creates a macOS host-mode network interface and bridges it to the
// guest's virtio-net device. The vCPU thread reads/writes vmnet
// directly during MMIO exits — no separate RX thread, no queues.
//
// Requires root privileges for vmnet_start_interface in host mode.

use crate::hvf;
use crate::virtio;

/// Virtio net header size (12 bytes for VIRTIO_F_VERSION_1).
const VIRTIO_NET_HDR_SIZE: usize = 12;

/// Wrapper to make vmnet::Interface Send (it holds a raw pointer
/// to the vmnet C interface which is thread-safe but not marked
/// as such in the Rust crate).
struct SendIface(vmnet::Interface);
unsafe impl Send for SendIface {}

/// Raw pointer to vmnet interface. After start(), only the vCPU
/// thread accesses it (read in check_rx, write in process_tx).
static IFACE_PTR: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Start vmnet in host mode. Returns the MAC address.
pub fn start() -> Result<[u8; 6], String> {
    let iface = vmnet::Interface::new(
        vmnet::mode::Mode::Host(Default::default()),
        Default::default(),
    ).map_err(|e| format!("vmnet::Interface::new: {e:?}"))?;

    let params: Vec<vmnet::parameters::Parameter> = iface.parameters().into();
    let mut mac_bytes = [0u8; 6];
    for p in &params {
        if let vmnet::parameters::Parameter::MACAddress(ref s) = p {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() == 6 {
                for (i, part) in parts.iter().enumerate() {
                    mac_bytes[i] = u8::from_str_radix(part, 16).unwrap_or(0);
                }
            }
        }
    }
    for p in &params { eprintln!("(vmnet) {p:?}"); }

    // Leak the interface. After this point only the vCPU thread uses it.
    let ptr = Box::into_raw(Box::new(SendIface(iface)));
    IFACE_PTR.store(ptr as usize, std::sync::atomic::Ordering::Release);

    Ok(mac_bytes)
}

/// Process the guest TX queue: walk the avail ring, extract frames,
/// write them to vmnet. Called from the vCPU thread on QUEUE_NOTIFY=1.
pub fn process_tx() {
    let mut dev_lock = virtio::DEVICE.lock().unwrap();
    let dev = match dev_lock.as_mut() {
        Some(d) => d,
        None => return,
    };

    let q = dev.queue(1); // TX queue
    if !q.ready { return; }

    let desc_base = q.desc_addr();
    let avail_base = q.avail_addr();
    let used_base = q.used_addr();
    let qsize = q.num as u16;
    if qsize == 0 { return; }

    let avail_idx = unsafe {
        let p = dev.gpa_to_host(avail_base + 2) as *const u16;
        core::ptr::read_volatile(p)
    };

    static TX_LAST: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
    let mut last = TX_LAST.load(std::sync::atomic::Ordering::Relaxed);

    let mut frames = Vec::new(); // collect frames to send outside the dev lock
    while last != avail_idx {
        let ring_idx = last & (qsize - 1);
        let desc_idx = unsafe {
            let p = dev.gpa_to_host(avail_base + 4 + ring_idx as u64 * 2) as *const u16;
            core::ptr::read_volatile(p)
        };

        let (addr, len) = unsafe {
            let dp = dev.gpa_to_host(desc_base + desc_idx as u64 * 16);
            let a = core::ptr::read_unaligned(dp as *const u64);
            let l = core::ptr::read_unaligned(dp.add(8) as *const u32);
            (a, l as usize)
        };

        if len > VIRTIO_NET_HDR_SIZE {
            let frame = unsafe {
                let ptr = dev.gpa_to_host(addr).add(VIRTIO_NET_HDR_SIZE);
                std::slice::from_raw_parts(ptr, len - VIRTIO_NET_HDR_SIZE).to_vec()
            };
            frames.push(frame);
        }

        // Mark as used.
        let used_idx = unsafe {
            let p = dev.gpa_to_host(used_base + 2) as *const u16;
            core::ptr::read_volatile(p)
        };
        let used_ring_idx = used_idx & (qsize - 1);
        unsafe {
            let entry = dev.gpa_to_host(used_base + 4 + used_ring_idx as u64 * 8);
            core::ptr::write_unaligned(entry as *mut u32, desc_idx as u32);
            core::ptr::write_unaligned(entry.add(4) as *mut u32, len as u32);
            let idx_ptr = dev.gpa_to_host(used_base + 2) as *mut u16;
            core::ptr::write_volatile(idx_ptr, used_idx.wrapping_add(1));
        }

        last = last.wrapping_add(1);
    }
    TX_LAST.store(last, std::sync::atomic::Ordering::Relaxed);

    if !frames.is_empty() {
        dev.interrupt_status |= 1;
        // DSB to flush used-ring writes to guest before releasing lock.
        unsafe { core::arch::asm!("dsb sy", options(nostack)); }
        drop(dev_lock);

        // Write frames directly to vmnet.
        let ptr = IFACE_PTR.load(std::sync::atomic::Ordering::Acquire);
        if ptr != 0 {
            let iface = unsafe { &mut *(ptr as *mut SendIface) };
            for frame in &frames {
                let _ = iface.0.write(frame);
            }
        }

        // Interrupt the guest.
        unsafe { hvf::hv_gic_set_spi(35, true); }
    }
}

/// Snoop DHCP ACK frames to learn the VM's IP address.
fn snoop_dhcp_ack(frame: &[u8]) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.load(Ordering::Relaxed) { return; }

    if frame.len() < 286 { return; }
    if frame[12] != 0x08 || frame[13] != 0x00 { return; }
    let ip_hdr_len = ((frame[14] & 0x0F) as usize) * 4;
    let ip_start = 14;
    if frame[ip_start + 9] != 17 { return; }
    let udp_start = ip_start + ip_hdr_len;
    if udp_start + 8 > frame.len() { return; }
    let src_port = u16::from_be_bytes([frame[udp_start], frame[udp_start + 1]]);
    let dst_port = u16::from_be_bytes([frame[udp_start + 2], frame[udp_start + 3]]);
    if src_port != 67 || dst_port != 68 { return; }
    let dhcp_start = udp_start + 8;
    if dhcp_start + 240 > frame.len() { return; }
    if frame[dhcp_start] != 2 { return; }
    let yiaddr = std::net::Ipv4Addr::new(
        frame[dhcp_start + 16], frame[dhcp_start + 17],
        frame[dhcp_start + 18], frame[dhcp_start + 19],
    );
    let magic_offset = dhcp_start + 236;
    if magic_offset + 4 > frame.len() { return; }
    if &frame[magic_offset..magic_offset + 4] != &[0x63, 0x82, 0x53, 0x63] { return; }
    let opts_start = magic_offset + 4;
    let mut i = opts_start;
    let mut msg_type = 0u8;
    while i < frame.len() {
        let opt = frame[i];
        if opt == 255 { break; }
        if opt == 0 { i += 1; continue; }
        if i + 1 >= frame.len() { break; }
        let opt_len = frame[i + 1] as usize;
        if i + 2 + opt_len > frame.len() { break; }
        if opt == 53 && opt_len >= 1 { msg_type = frame[i + 2]; }
        i += 2 + opt_len;
    }
    if msg_type != 5 { return; }

    DONE.store(true, Ordering::Relaxed);
    eprintln!();
    eprintln!("  VM ready: http://{yiaddr}:80/");
    eprintln!("  Benchmark: wrk -t1 -c1 -d10s http://{yiaddr}:80/health");
    eprintln!();
}

/// Read frames from vmnet and inject directly into the guest RX queue.
/// Called from the vCPU thread on every MMIO exit (~800K/sec). No
/// separate RX thread — vmnet's kernel buffer holds frames between calls.
pub fn check_rx() {
    static RX_LAST: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

    let ptr = IFACE_PTR.load(std::sync::atomic::Ordering::Acquire);
    if ptr == 0 { return; }
    let iface = unsafe { &mut *(ptr as *mut SendIface) };

    let mut dev_lock = virtio::DEVICE.lock().unwrap();
    let dev = match dev_lock.as_mut() {
        Some(d) => d,
        None => return,
    };

    let q = dev.queue(0);
    if !q.ready { return; }

    let desc_base = q.desc_addr();
    let avail_base = q.avail_addr();
    let used_base = q.used_addr();
    let qsize = q.num as u16;
    if qsize == 0 { return; }

    let mut injected = 0u32;
    let mut buf = [0u8; 2048];

    loop {
        // Check for free descriptors before reading vmnet.
        let avail_idx = unsafe {
            core::ptr::read_volatile(dev.gpa_to_host(avail_base + 2) as *const u16)
        };
        let last = RX_LAST.load(std::sync::atomic::Ordering::Relaxed);
        if last == avail_idx { break; } // ring full

        // Non-blocking read from vmnet.
        let n = match iface.0.read(&mut buf) {
            Ok(n) if n > 0 => n,
            _ => break, // no more frames
        };

        snoop_dhcp_ack(&buf[..n]);

        // Inject into guest RX ring.
        let ring_idx = last & (qsize - 1);
        let desc_idx = unsafe {
            core::ptr::read_volatile(
                dev.gpa_to_host(avail_base + 4 + ring_idx as u64 * 2) as *const u16
            )
        };
        let addr = unsafe {
            core::ptr::read_unaligned(
                dev.gpa_to_host(desc_base + desc_idx as u64 * 16) as *const u64
            )
        };

        let total_len = VIRTIO_NET_HDR_SIZE + n;
        unsafe {
            let dest = dev.gpa_to_host(addr);
            core::ptr::write_bytes(dest, 0, VIRTIO_NET_HDR_SIZE);
            core::ptr::copy_nonoverlapping(buf.as_ptr(), dest.add(VIRTIO_NET_HDR_SIZE), n);
        }

        // Update used ring.
        let used_idx = unsafe {
            core::ptr::read_volatile(dev.gpa_to_host(used_base + 2) as *const u16)
        };
        let new_used_idx = used_idx.wrapping_add(1);
        unsafe {
            let entry = dev.gpa_to_host(used_base + 4 + (used_idx & (qsize - 1)) as u64 * 8);
            core::ptr::write_unaligned(entry as *mut u32, desc_idx as u32);
            core::ptr::write_unaligned(entry.add(4) as *mut u32, total_len as u32);
            core::ptr::write_volatile(
                dev.gpa_to_host(used_base + 2) as *mut u16,
                new_used_idx,
            );
        }
        RX_LAST.store(last.wrapping_add(1), std::sync::atomic::Ordering::Relaxed);
        dev.used_idx[0] = new_used_idx;
        dev.interrupt_status |= 1;
        injected += 1;
    }

    if injected > 0 {
        unsafe { core::arch::asm!("dsb sy", options(nostack)); }
        unsafe { hvf::hv_gic_set_spi(35, true); }
    }
}
