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

// FFI for vmnet and GCD APIs.
extern "C" {
    fn dispatch_queue_create(
        label: *const std::ffi::c_char,
        attr: *const std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    fn vmnet_interface_set_event_callback(
        interface: *mut std::ffi::c_void,
        event_mask: u32,
        queue: *mut std::ffi::c_void,
        handler: *mut std::ffi::c_void,
    ) -> u32;
    fn vmnet_read(
        interface: *mut std::ffi::c_void,
        packets: *mut libc::iovec,  // actually *mut vmpktdesc
        pktcnt: *mut i32,
    ) -> u32;
}

/// Batch-read from vmnet (up to 128 packets).
/// Returns frames read from the raw vmnet C API.
unsafe fn vmnet_batch_read(iface_ref: *mut std::ffi::c_void) -> Vec<Vec<u8>> {
    const MAX_PKTS: usize = 128;
    let mut bufs = [[0u8; 2048]; MAX_PKTS];
    let mut iovecs: [libc::iovec; MAX_PKTS] = std::mem::zeroed();
    // vmpktdesc layout: { vm_pkt_size: usize, vm_pkt_iov: *mut iovec, vm_pkt_iovcnt: u32, vm_flags: u32 }
    #[repr(C)]
    struct VmPktDesc {
        vm_pkt_size: usize,
        vm_pkt_iov: *mut libc::iovec,
        vm_pkt_iovcnt: u32,
        vm_flags: u32,
    }
    let mut descs: [VmPktDesc; MAX_PKTS] = std::mem::zeroed();
    for i in 0..MAX_PKTS {
        iovecs[i].iov_base = bufs[i].as_mut_ptr() as *mut _;
        iovecs[i].iov_len = 2048;
        descs[i].vm_pkt_size = 2048;
        descs[i].vm_pkt_iov = &mut iovecs[i];
        descs[i].vm_pkt_iovcnt = 1;
        descs[i].vm_flags = 0;
    }
    let mut pktcnt = MAX_PKTS as i32;
    let rc = vmnet_read(iface_ref, descs.as_mut_ptr() as *mut _, &mut pktcnt);
    if rc != 1000 || pktcnt <= 0 { return Vec::new(); }
    let mut frames = Vec::with_capacity(pktcnt as usize);
    for i in 0..pktcnt as usize {
        let len = descs[i].vm_pkt_size;
        if len > 0 && len <= 2048 {
            frames.push(bufs[i][..len].to_vec());
        }
    }
    frames
}

/// Virtio net header size (12 bytes for VIRTIO_F_VERSION_1).
const VIRTIO_NET_HDR_SIZE: usize = 12;

/// Wrapper to make vmnet::Interface Send+Sync (it holds a raw pointer
/// to the vmnet C interface which is thread-safe for read/write but
/// not marked as such in the Rust crate).
struct SendIface(vmnet::Interface);
unsafe impl Send for SendIface {}

/// Global vmnet interface, behind a Mutex because read/write need &mut.
static IFACE: Mutex<Option<SendIface>> = Mutex::new(None);

/// Start vmnet via a helper subprocess. Returns the MAC address.
/// The helper owns the vmnet interface in a separate process to avoid
/// GCD thread starvation from hv_vcpu_run in the parent.
pub fn start() -> Result<[u8; 6], String> {
    let (mac_bytes, child_fd) = crate::vmnet_helper::spawn()?;
    HELPER_FD.store(child_fd as usize, std::sync::atomic::Ordering::Release);

    // Spawn RX reader thread: reads datagrams from the helper socket.
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        loop {
            let n = unsafe {
                libc::recv(child_fd, buf.as_mut_ptr() as *mut _, buf.len(), 0)
            };
            if n <= 0 {
                std::thread::sleep(std::time::Duration::from_micros(50));
                continue;
            }
            let frame = &buf[..n as usize];
            snoop_dhcp_ack(frame);
            RX_PENDING.lock().unwrap().push_back(frame.to_vec());
            // Signal that frames are available (debounced — don't kick
            // on every frame to avoid VM exit thrashing).
            unsafe { hvf::hv_gic_set_spi(35, true); }
        }
    });

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

        // Send frames to the helper subprocess via Unix socket.
        let fd = HELPER_FD.load(std::sync::atomic::Ordering::Acquire) as i32;
        if fd > 0 {
            for frame in &frames {
                unsafe {
                    libc::send(fd, frame.as_ptr() as *const _, frame.len(), 0);
                }
            }
        }

        // Interrupt the guest.
        unsafe { hvf::hv_gic_set_spi(35, true); }
    }
}

/// Pending RX frames buffered by the background thread, waiting for the
/// vCPU thread to inject them via check_rx().
static RX_PENDING: Mutex<VecDeque<Vec<u8>>> = Mutex::new(VecDeque::new());

/// File descriptor for the helper subprocess socket.
static HELPER_FD: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Check if RX_PENDING has frames waiting.
pub fn rx_pending_empty() -> bool {
    RX_PENDING.lock().unwrap().is_empty()
}


/// vCPU ID for hv_vcpus_exit kicks. Set by the vCPU thread before run().
pub static VCPU_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Raw pointer to vmnet interface for lock-free access.
/// SAFETY: vmnet's C API (vmnet_read/vmnet_write) is thread-safe.
/// The Rust crate doesn't mark it Send+Sync but the underlying C
/// implementation uses internal serialization.
static IFACE_PTR: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Raw InterfaceRef for batch reads via the C API.
static VMNET_IFACE_REF: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Read all available frames from vmnet and push to RX_PENDING.
/// Uses batch read (up to 128 packets per vmnet_read call).
unsafe fn drain_vmnet_rx() -> bool {
    let iface_ref = VMNET_IFACE_REF.load(std::sync::atomic::Ordering::Acquire) as *mut std::ffi::c_void;
    if iface_ref.is_null() {
        // Fallback to single-packet read via the Rust crate.
        let ptr = IFACE_PTR.load(std::sync::atomic::Ordering::Acquire);
        if ptr == 0 { return false; }
        let iface = &mut *(ptr as *mut SendIface);
        let mut buf = [0u8; 2048];
        let mut got_any = false;
        loop {
            match iface.0.read(&mut buf) {
                Ok(n) if n > 0 => {
                    snoop_dhcp_ack(&buf[..n]);
                    RX_PENDING.lock().unwrap().push_back(buf[..n].to_vec());
                    got_any = true;
                }
                _ => break,
            }
        }
        return got_any;
    }

    // Batch read via raw C API.
    let frames = vmnet_batch_read(iface_ref);
    if frames.is_empty() { return false; }
    let mut pending = RX_PENDING.lock().unwrap();
    for frame in &frames {
        snoop_dhcp_ack(frame);
        pending.push_back(frame.clone());
    }
    true
}

/// Notify the vCPU that new RX frames are available.
fn kick_vcpu() {
    unsafe { hvf::hv_gic_set_spi(35, true); }
    let vcpu = VCPU_ID.load(std::sync::atomic::Ordering::Relaxed);
    if vcpu != 0 {
        unsafe { hvf::hv_vcpus_exit(&vcpu as *const u64, 1); }
    }
}

/// Set up vmnet IO: event callback + polling thread.
///
/// The GCD callback reads packets and returns immediately (no blocking
/// HVF calls). A separate notify thread kicks the vCPU asynchronously.
fn start_io() {
    // Leak the interface into a raw pointer for lock-free access.
    let iface = IFACE.lock().unwrap().take().unwrap();
    let ptr = Box::into_raw(Box::new(iface));
    IFACE_PTR.store(ptr as usize, std::sync::atomic::Ordering::Release);

    // Create a high-priority serial dispatch queue for vmnet events.
    // The default global queue used by the vmnet Rust crate gets starved
    // by hv_vcpu_run (which monopolizes the vCPU thread in the kernel).
    // A dedicated queue with user-interactive QoS ensures GCD schedules
    // the vmnet callback promptly on a separate core.
    extern "C" {
        fn dispatch_queue_create_with_target(
            label: *const std::ffi::c_char,
            attr: *const std::ffi::c_void,
            target: *mut std::ffi::c_void,
        ) -> *mut std::ffi::c_void;
        fn dispatch_get_global_queue(
            identifier: isize,
            flags: usize,
        ) -> *mut std::ffi::c_void;
    }
    // QOS_CLASS_USER_INTERACTIVE = 0x21
    let hi_queue = unsafe { dispatch_get_global_queue(0x21, 0) };
    let serial_queue = unsafe {
        dispatch_queue_create_with_target(
            c"com.unikernel.vmnet".as_ptr(),
            std::ptr::null(),  // NULL = serial
            hi_queue,          // target = user-interactive global queue
        )
    };

    // Get the raw InterfaceRef for batch reads via the C API.
    // vmnet::Interface struct layout: queue(*void), interface(*void), ...
    let iface_ref: *mut std::ffi::c_void = unsafe {
        let base = &(*ptr).0 as *const vmnet::Interface as *const u8;
        *(base.add(std::mem::size_of::<*mut std::ffi::c_void>()) as *const *mut std::ffi::c_void)
    };
    VMNET_IFACE_REF.store(iface_ref as usize, std::sync::atomic::Ordering::Release);

    // Register PACKETS_AVAILABLE callback on the serial queue.
    // Use a raw Objective-C block (ABI-compatible struct) instead
    // of depending on the `block` crate.
    #[repr(C)]
    struct Block {
        isa: *const std::ffi::c_void,
        flags: i32,
        reserved: i32,
        invoke: unsafe extern "C" fn(*mut Block, u32, *mut std::ffi::c_void),
        descriptor: *const BlockDescriptor,
    }
    #[repr(C)]
    struct BlockDescriptor {
        reserved: u64,
        size: u64,
    }
    static DESCRIPTOR: BlockDescriptor = BlockDescriptor {
        reserved: 0,
        size: std::mem::size_of::<Block>() as u64,
    };
    unsafe extern "C" fn invoke_cb(_block: *mut Block, _events: u32, _xdict: *mut std::ffi::c_void) {
        if drain_vmnet_rx() {
            kick_vcpu();
        }
    }
    extern "C" { static _NSConcreteGlobalBlock: *const std::ffi::c_void; }
    static mut BLOCK: Block = Block {
        isa: std::ptr::null(), // set below
        flags: 1 << 28, // BLOCK_IS_GLOBAL
        reserved: 0,
        invoke: invoke_cb,
        descriptor: &DESCRIPTOR,
    };
    unsafe {
        BLOCK.isa = _NSConcreteGlobalBlock;
        let rc = vmnet_interface_set_event_callback(
            iface_ref,
            1, // VMNET_INTERFACE_PACKETS_AVAILABLE
            serial_queue,
            &mut BLOCK as *mut _ as *mut std::ffi::c_void,
        );
        if rc != 1000 {
            eprintln!("(vmnet) set_event_callback on serial queue failed: rc={rc}");
        }
    }

    // Fallback polling thread in case the serial queue callback isn't
    // enough. 1ms poll with burst drain.
    std::thread::spawn(|| {
        loop {
            unsafe {
                if drain_vmnet_rx() {
                    kick_vcpu();
                    loop {
                        std::thread::sleep(std::time::Duration::from_micros(100));
                        if !drain_vmnet_rx() { break; }
                        kick_vcpu();
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    });
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

    // Drain ALL buffered frames from the callback/polling thread.
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
