// tools/hvf-runner/src/vmnet_net.rs
//
// vmnet.framework integration via the `vmnet` crate.
//
// Creates a macOS NAT (shared mode) network interface and bridges
// it to the guest's virtio-net device. No userspace TCP/UDP proxy.
//
// Requires root privileges for vmnet_start_interface in shared mode.

use std::sync::Mutex;

use crate::hvf;
use crate::virtio;

/// Virtio net header size (12 bytes for VIRTIO_F_VERSION_1).
const VIRTIO_NET_HDR_SIZE: usize = 12;

/// Wrapper to make vmnet::Interface Send+Sync (it holds a raw pointer
/// to the vmnet C interface which is thread-safe for read/write but
/// not marked as such in the Rust crate).
struct SendIface(vmnet::Interface);
unsafe impl Send for SendIface {}

/// Global vmnet interface, behind a Mutex because read/write need &mut.
static IFACE: Mutex<Option<SendIface>> = Mutex::new(None);

/// Start a vmnet shared-mode interface and spawn an RX polling thread.
/// Returns the MAC address assigned by vmnet.
pub fn start() -> Result<[u8; 6], String> {
    let iface = vmnet::Interface::new(
        vmnet::mode::Mode::Shared(Default::default()),
        Default::default(),
    ).map_err(|e| format!("vmnet::Interface::new: {e:?}"))?;

    // Extract MAC from parameters.
    let params: Vec<vmnet::parameters::Parameter> = iface.parameters().into();
    let mut mac_bytes = [0u8; 6];
    for p in &params {
        if let vmnet::parameters::Parameter::MACAddress(ref s) = p {
            // MAC is like "aa:bb:cc:dd:ee:ff"
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() == 6 {
                for (i, part) in parts.iter().enumerate() {
                    mac_bytes[i] = u8::from_str_radix(part, 16).unwrap_or(0);
                }
            }
        }
    }

    eprintln!(
        "(vmnet) interface up: MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac_bytes[0], mac_bytes[1], mac_bytes[2],
        mac_bytes[3], mac_bytes[4], mac_bytes[5],
    );

    *IFACE.lock().unwrap() = Some(SendIface(iface));

    // Spawn RX polling thread.
    std::thread::spawn(rx_loop);

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
        drop(dev_lock); // release virtio lock before vmnet I/O

        // Send all frames to vmnet.
        let mut iface_lock = IFACE.lock().unwrap();
        if let Some(ref mut iface) = *iface_lock {
            for frame in &frames {
                let _ = iface.0.write(frame);
            }
        }

        // Interrupt the guest.
        unsafe { hvf::hv_gic_set_spi(35, true); }
    }
}

/// RX polling loop: reads frames from vmnet and injects into guest RX queue.
fn rx_loop() {
    static RX_LAST: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
    let mut buf = vec![0u8; 2048];

    loop {
        // Read a frame from vmnet.
        let n = {
            let mut iface_lock = IFACE.lock().unwrap();
            match iface_lock.as_mut() {
                Some(iface) => match iface.0.read(&mut buf) {
                    Ok(n) if n > 0 => n,
                    _ => 0,
                },
                None => 0,
            }
        };

        if n == 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
            continue;
        }

        // Inject into guest RX queue.
        let mut dev_lock = virtio::DEVICE.lock().unwrap();
        let dev = match dev_lock.as_mut() {
            Some(d) => d,
            None => continue,
        };

        let q = dev.queue(0); // RX queue
        if !q.ready { continue; }

        let desc_base = q.desc_addr();
        let avail_base = q.avail_addr();
        let used_base = q.used_addr();
        let qsize = q.num as u16;
        if qsize == 0 { continue; }

        let avail_idx = unsafe {
            let p = dev.gpa_to_host(avail_base + 2) as *const u16;
            core::ptr::read_volatile(p)
        };
        let mut last = RX_LAST.load(std::sync::atomic::Ordering::Relaxed);

        if last == avail_idx {
            continue; // no free RX buffers
        }

        let ring_idx = last & (qsize - 1);
        let desc_idx = unsafe {
            let p = dev.gpa_to_host(avail_base + 4 + ring_idx as u64 * 2) as *const u16;
            core::ptr::read_volatile(p)
        };

        let (addr, _buf_len) = unsafe {
            let dp = dev.gpa_to_host(desc_base + desc_idx as u64 * 16);
            let a = core::ptr::read_unaligned(dp as *const u64);
            let l = core::ptr::read_unaligned(dp.add(8) as *const u32);
            (a, l as usize)
        };

        // Write virtio_net_hdr (12 zero bytes) + frame.
        let total_len = VIRTIO_NET_HDR_SIZE + n;
        unsafe {
            let dest = dev.gpa_to_host(addr);
            core::ptr::write_bytes(dest, 0, VIRTIO_NET_HDR_SIZE);
            core::ptr::copy_nonoverlapping(buf.as_ptr(), dest.add(VIRTIO_NET_HDR_SIZE), n);
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
            core::ptr::write_unaligned(entry.add(4) as *mut u32, total_len as u32);
            let idx_ptr = dev.gpa_to_host(used_base + 2) as *mut u16;
            core::ptr::write_volatile(idx_ptr, used_idx.wrapping_add(1));
        }

        last = last.wrapping_add(1);
        RX_LAST.store(last, std::sync::atomic::Ordering::Relaxed);

        // Interrupt the guest.
        dev.interrupt_status |= 1;
        drop(dev_lock);
        unsafe { hvf::hv_gic_set_spi(35, true); }
    }
}
