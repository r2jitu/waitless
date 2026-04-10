// tools/hvf-runner/src/vmnet_net.rs
//
// vmnet.framework integration via the `vmnet` crate.
//
// Creates a macOS NAT (shared mode) network interface and bridges
// it to the guest's virtio-net device. No userspace TCP/UDP proxy.
//
// Requires root privileges for vmnet_start_interface in shared mode.

use std::collections::VecDeque;
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

/// Start a vmnet host-mode interface and spawn an RX polling thread.
/// Returns the MAC address assigned by vmnet.
pub fn start() -> Result<[u8; 6], String> {
    let iface = vmnet::Interface::new(
        vmnet::mode::Mode::Host(Default::default()),
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

    // Print all vmnet parameters for diagnostics.
    for p in &params {
        eprintln!("(vmnet) param: {p:?}");
    }

    *IFACE.lock().unwrap() = Some(SendIface(iface));

    // Spawn an RX thread that reads frames from vmnet and wakes the
    // vCPU via hv_vcpus_exit. The actual frame injection into the guest
    // virtqueue happens in check_rx() on the vCPU thread for cache
    // coherency. The RX thread just buffers the frames and kicks.
    std::thread::spawn(rx_notify_loop);

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

        // Queue frames for the IO thread (which owns the vmnet interface).
        TX_OUTBOUND.lock().unwrap().extend(frames);
        // Wake the IO thread to drain TX immediately.
        if let Some(ref tx) = *TX_WAKE.lock().unwrap() {
            let _ = tx.try_send(());
        }

        // Interrupt the guest.
        unsafe { hvf::hv_gic_set_spi(35, true); }
    }
}

/// Pending RX frames buffered by the background thread, waiting for the
/// vCPU thread to inject them via check_rx().
static RX_PENDING: Mutex<VecDeque<Vec<u8>>> = Mutex::new(VecDeque::new());

/// Pending TX frames from the vCPU thread, waiting for the RX/IO thread
/// to write them to vmnet. This avoids sharing the vmnet interface
/// between threads (eliminates IFACE mutex contention).
static TX_OUTBOUND: Mutex<VecDeque<Vec<u8>>> = Mutex::new(VecDeque::new());

/// vCPU ID for hv_vcpus_exit kicks. Set by the vCPU thread before run().
pub static VCPU_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Channel sender to wake the IO thread when TX frames are queued.
static TX_WAKE: Mutex<Option<std::sync::mpsc::SyncSender<()>>> = Mutex::new(None);

/// Background IO thread: event-driven read from vmnet + drain TX queue.
///
/// Uses vmnet's PACKETS_AVAILABLE event callback (via GCD dispatch queue)
/// to wake only when data is available, instead of busy-polling. This
/// eliminates the ~100ms latency caused by yield_now() scheduler jitter.
fn rx_notify_loop() {
    let mut buf = [0u8; 2048];
    // Take ownership of the vmnet interface — only this thread touches it.
    let mut iface = IFACE.lock().unwrap().take().unwrap();

    // Unified wake channel: vmnet RX callback and TX path both signal here.
    let (wake_tx, wake_rx) = std::sync::mpsc::sync_channel::<()>(1);

    // Register event callback: vmnet signals us when packets are available.
    let rx_wake = wake_tx.clone();
    iface.0.set_event_callback(vmnet::Events::PACKETS_AVAILABLE, move |_, _| {
        let _ = rx_wake.try_send(());
    }).expect("set_event_callback failed");

    // Store the TX sender so process_tx() can wake us.
    *TX_WAKE.lock().unwrap() = Some(wake_tx);

    let mut io_count: u64 = 0;

    loop {
        io_count += 1;

        // 1. Drain TX outbound queue → write to vmnet.
        {
            let mut txq = TX_OUTBOUND.lock().unwrap();
            while let Some(frame) = txq.pop_front() {
                let t = std::time::Instant::now();
                let _ = iface.0.write(&frame);
                if io_count <= 50 {
                    eprintln!("(io) vmnet_write: {:?}", t.elapsed());
                }
            }
        }

        // 2. Read ALL available packets from vmnet (non-blocking).
        let mut got_any = false;
        loop {
            let t = std::time::Instant::now();
            match iface.0.read(&mut buf) {
                Ok(n) if n > 0 => {
                    if io_count <= 50 {
                        eprintln!("(io) vmnet_read({n}B): {:?}", t.elapsed());
                    }
                    snoop_dhcp_ack(&buf[..n]);
                    RX_PENDING.lock().unwrap().push_back(buf[..n].to_vec());
                    got_any = true;
                }
                _ => break,
            }
        }

        if got_any {
            let vcpu = VCPU_ID.load(std::sync::atomic::Ordering::Relaxed);
            if vcpu != 0 {
                unsafe { hvf::hv_vcpus_exit(&vcpu as *const u64, 1); }
            }
            continue;
        }

        // 3. Block until woken by RX event callback or TX queue.
        let t = std::time::Instant::now();
        let _ = wake_rx.recv();
        if io_count <= 50 {
            eprintln!("(io) wake after {:?}", t.elapsed());
        }
    }
}

/// Snoop DHCP ACK frames to learn the VM's IP and set up port forwarding.
/// Called from the RX thread for every received frame.
fn snoop_dhcp_ack(frame: &[u8]) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static FORWARDED: AtomicBool = AtomicBool::new(false);
    if FORWARDED.load(Ordering::Relaxed) { return; }

    // Minimum: 14 (eth) + 20 (ip) + 8 (udp) + 240 (dhcp base) + 4 (option 53)
    if frame.len() < 286 { return; }

    // Check ethertype = IPv4 (0x0800)
    if frame[12] != 0x08 || frame[13] != 0x00 { return; }

    // Check IP protocol = UDP (17)
    let ip_hdr_len = ((frame[14] & 0x0F) as usize) * 4;
    let ip_start = 14;
    if frame[ip_start + 9] != 17 { return; }

    // Check UDP src=67, dst=68 (DHCP server → client)
    let udp_start = ip_start + ip_hdr_len;
    if udp_start + 8 > frame.len() { return; }
    let src_port = u16::from_be_bytes([frame[udp_start], frame[udp_start + 1]]);
    let dst_port = u16::from_be_bytes([frame[udp_start + 2], frame[udp_start + 3]]);
    if src_port != 67 || dst_port != 68 { return; }

    // DHCP starts at udp_start + 8
    let dhcp_start = udp_start + 8;
    if dhcp_start + 240 > frame.len() { return; }

    // op=2 (BOOTREPLY)
    if frame[dhcp_start] != 2 { return; }

    // yiaddr at offset 16 from DHCP start
    let yiaddr = std::net::Ipv4Addr::new(
        frame[dhcp_start + 16], frame[dhcp_start + 17],
        frame[dhcp_start + 18], frame[dhcp_start + 19],
    );

    // Parse options to find msg_type=5 (ACK)
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

    if msg_type != 5 { return; } // Only on ACK

    eprintln!("(vmnet) DHCP ACK: VM IP = {yiaddr}");

    // Spawn a TCP proxy: listen on localhost:8080, forward to VM:80.
    let ip = yiaddr;
    FORWARDED.store(true, Ordering::Relaxed);
    std::thread::spawn(move || {
        tcp_proxy(ip, 8080, 80);
    });
}

/// Simple TCP proxy: listen on localhost:host_port, forward to vm_ip:vm_port.
fn tcp_proxy(vm_ip: std::net::Ipv4Addr, host_port: u16, vm_port: u16) {
    use std::net::{TcpListener, TcpStream, SocketAddr};

    let listener = match TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], host_port))) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("(proxy) failed to bind localhost:{host_port}: {e}");
            return;
        }
    };
    eprintln!("(proxy) listening on localhost:{host_port} → {vm_ip}:{vm_port}");

    for stream in listener.incoming() {
        let client = match stream {
            Ok(s) => s,
            Err(e) => { eprintln!("(proxy) accept error: {e}"); continue; }
        };

        let vm_addr = SocketAddr::from((vm_ip, vm_port));
        let vm_ip_copy = vm_ip;
        std::thread::spawn(move || {
            let upstream = match TcpStream::connect_timeout(
                &vm_addr,
                std::time::Duration::from_secs(5),
            ) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("(proxy) connect to {vm_ip_copy}:{vm_port} failed: {e}");
                    return;
                }
            };
            proxy_connection(client, upstream);
        });
    }
}

fn proxy_connection(
    mut client: std::net::TcpStream,
    mut upstream: std::net::TcpStream,
) {
    use std::io::{Read, Write};

    let mut client2 = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut upstream2 = match upstream.try_clone() {
        Ok(u) => u,
        Err(_) => return,
    };

    // Client → Upstream
    let h1 = std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            let n = match client.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if upstream.write_all(&buf[..n]).is_err() { break; }
        }
        let _ = upstream.shutdown(std::net::Shutdown::Write);
    });

    // Upstream → Client
    let h2 = std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            let n = match upstream2.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if client2.write_all(&buf[..n]).is_err() { break; }
        }
        let _ = client2.shutdown(std::net::Shutdown::Write);
    });

    let _ = h1.join();
    let _ = h2.join();
}

/// Check for pending RX frames from vmnet and inject into guest RX queue.
/// Called from the vCPU thread during MMIO dispatch to ensure cache
/// coherency — host writes to guest RAM are only guaranteed visible to
/// the guest when done from the same CPU context.
pub fn check_rx() {
    static RX_LAST: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

    // Drain ALL buffered frames from the RX thread.
    let mut injected = 0u32;

    loop {
        let frame = match RX_PENDING.lock().unwrap().pop_front() {
            Some(f) => f,
            None => break,
        };
        let buf = &frame;
        let n = buf.len();

        let mut dev_lock = virtio::DEVICE.lock().unwrap();
        let dev = match dev_lock.as_mut() {
            Some(d) => d,
            None => break,
        };

        let q = dev.queue(0);
        if !q.ready { break; }

        let desc_base = q.desc_addr();
        let avail_base = q.avail_addr();
        let used_base = q.used_addr();
        let qsize = q.num as u16;
        if qsize == 0 { break; }

        let avail_idx = unsafe {
            core::ptr::read_volatile(dev.gpa_to_host(avail_base + 2) as *const u16)
        };
        let last = RX_LAST.load(std::sync::atomic::Ordering::Relaxed);

        if last == avail_idx { break; } // no free descriptors

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

        // Write virtio_net_hdr (12 zero bytes) + frame into descriptor buffer.
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
        dev.used_idx[0] = new_used_idx; // Update MMIO-visible used_idx
        dev.interrupt_status |= 1;
        injected += 1;
    }

    if injected > 0 {
        // Ensure all writes to guest RAM (descriptor data + used ring)
        // are visible to the guest vCPU before it resumes. On Apple
        // Silicon, the host and guest share the Inner Shareable domain,
        // so DSB SY makes host writes visible at L2 before the guest's
        // dcache lookup can bypass them.
        unsafe { core::arch::asm!("dsb sy", options(nostack)); }
        unsafe { hvf::hv_gic_set_spi(35, true); }
    }
}
