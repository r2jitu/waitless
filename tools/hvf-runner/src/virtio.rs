// tools/hvf-runner/src/virtio.rs
//
// Virtio-MMIO device emulation for virtio-net.
//
// Implements the register file at a single MMIO address (0x0a000000).
// The kernel's virtio_net::init_mmio() probes this device, negotiates
// features, sets up queues (2 per vCPU + 1 ctrl), and drives it via
// QUEUE_NOTIFY. Packet I/O lives in `userspace_net.rs`, which owns
// the `QueueSnapshot`s this module publishes via `QUEUE_SNAPS`.
//
// ── SAFETY contract for the raw-pointer code in this module ──────
//
// All `unsafe { ... }` blocks here do raw-pointer reads and writes
// into guest RAM through the host mapping:
//
//   `ram_host + (gpa - ram_base) → *mut u8`
//
// The guest RAM mapping is created by `Vm::new_with_config` via
// `hv_vm_allocate` + `hv_vm_map` and lives for the entire VM
// lifetime. `QueueSnapshot` captures `{ram_host, ram_base, qsize,
// desc_addr, avail_addr, used_addr}` once at `QUEUE_READY` time and
// is published through `OnceLock` — the snapshot is immutable after
// publication, so readers on other threads see a consistent view.
//
// The `gpa_to_host` helper debug-asserts that the offset is inside
// the 1 GB mapping; the same bound holds in production (the guest
// driver can't point a descriptor outside its own ring). Writes to
// the used ring are bounded by `qsize` from the snapshot; reads
// from the avail ring use `read_volatile` to pick up publication
// by the guest driver.

use std::sync::Mutex;
use std::sync::OnceLock;

// ── Virtio-MMIO register offsets (must match drivers/virtio.rs) ──────────────

const MAGIC_VALUE: u64 = 0x000;
const VERSION: u64 = 0x004;
const DEVICE_ID: u64 = 0x008;
const VENDOR_ID: u64 = 0x00c;
const DEVICE_FEATURES: u64 = 0x010;
const DEVICE_FEATURES_SEL: u64 = 0x014;
const DRIVER_FEATURES: u64 = 0x020;
const DRIVER_FEATURES_SEL: u64 = 0x024;
const QUEUE_SEL: u64 = 0x030;
const QUEUE_NUM_MAX: u64 = 0x034;
const QUEUE_NUM: u64 = 0x038;
const QUEUE_READY: u64 = 0x044;
const QUEUE_NOTIFY: u64 = 0x050;
const INTERRUPT_STATUS: u64 = 0x060;
const INTERRUPT_ACK: u64 = 0x064;
const STATUS: u64 = 0x070;
const QUEUE_DESC_LOW: u64 = 0x080;
const QUEUE_DESC_HIGH: u64 = 0x084;
const QUEUE_DRIVER_LOW: u64 = 0x090;
const QUEUE_DRIVER_HIGH: u64 = 0x094;
const QUEUE_DEVICE_LOW: u64 = 0x0a0;
const QUEUE_DEVICE_HIGH: u64 = 0x0a4;
const CONFIG_BASE: u64 = 0x100;

// Virtio constants
const VIRTIO_MAGIC: u32 = 0x7472_6976;
const VIRTIO_VERSION_2: u32 = 2;
const VIRTIO_DEVICE_NET: u32 = 1;
const VIRTIO_VENDOR: u32 = 0x554d_4551; // "QEMU" — convention

// Feature bits we offer (word 0 only; word 1 = VIRTIO_F_VERSION_1 implied by v2)
const VIRTIO_NET_F_CSUM: u32 = 1 << 0;
const VIRTIO_NET_F_MAC: u32 = 1 << 5;
const VIRTIO_NET_F_HOST_TSO4: u32 = 1 << 11;
const VIRTIO_NET_F_CTRL_VQ: u32 = 1 << 17;
const VIRTIO_NET_F_MQ: u32 = 1 << 22;

// Status bits
const STATUS_FEATURES_OK: u32 = 8;

const QUEUE_SIZE: u32 = 256;
const MAX_VCPUS: usize = 8;
const MAX_QUEUES: usize = 2 * MAX_VCPUS + 1; // 2*N queue pairs + 1 ctrl VQ

#[derive(Default)]
pub struct QueueState {
    pub num: u32,
    pub ready: bool,
    desc_lo: u32,
    desc_hi: u32,
    driver_lo: u32,
    driver_hi: u32,
    device_lo: u32,
    device_hi: u32,
}

impl QueueState {
    pub fn desc_addr(&self) -> u64 {
        (self.desc_hi as u64) << 32 | self.desc_lo as u64
    }
    pub fn avail_addr(&self) -> u64 {
        (self.driver_hi as u64) << 32 | self.driver_lo as u64
    }
    pub fn used_addr(&self) -> u64 {
        (self.device_hi as u64) << 32 | self.device_lo as u64
    }
}

pub struct VirtioNet {
    status: u32,
    device_features_sel: u32,
    driver_features_sel: u32,
    driver_features: [u32; 2], // word 0 and word 1
    queue_sel: u32,
    num_queues: usize,
    queues: [QueueState; MAX_QUEUES],
    pub interrupt_status: u32,
    mac: [u8; 6],
    /// Host pointer to the start of guest RAM (for translating GPAs to host).
    ram_host: *mut u8,
    ram_base: u64,
    /// Current used_idx for each queue, updated by the vCPU thread's
    /// inline RX/TX drains in `userspace_net::poll_worker_iteration` /
    /// `process_tx_queue`.
    /// Read by the guest via device config at offset 0x110+queue*2
    /// to bypass dcache coherency issues on HVF.
    pub used_idx: [u16; MAX_QUEUES],
    /// Number of queue pairs (N). Total queues = 2*N (+ 1 ctrl if MQ).
    pub num_queue_pairs: u16,
}

// SAFETY: ram_host is a stable mapping for the VM's lifetime; only one
// thread (the vCPU) accesses VirtioNet during MMIO dispatch.
unsafe impl Send for VirtioNet {}

pub static DEVICE: Mutex<Option<VirtioNet>> = Mutex::new(None);

/// Snapshot of queue addresses + RAM mapping for lock-free access
/// from the IO/RX thread. Published once after guest driver init.
#[derive(Clone, Copy)]
pub struct QueueSnapshot {
    pub ram_host: *mut u8,
    pub ram_base: u64,
    pub desc_addr: u64,
    pub avail_addr: u64,
    pub used_addr: u64,
    pub qsize: u16,
    pub ready: bool,
}

unsafe impl Send for QueueSnapshot {}
unsafe impl Sync for QueueSnapshot {}

impl QueueSnapshot {
    pub const EMPTY: Self = QueueSnapshot {
        ram_host: std::ptr::null_mut(),
        ram_base: 0,
        desc_addr: 0,
        avail_addr: 0,
        used_addr: 0,
        qsize: 0,
        ready: false,
    };

    #[inline]
    pub fn gpa_to_host(&self, gpa: u64) -> *mut u8 {
        let offset = gpa.wrapping_sub(self.ram_base) as usize;
        debug_assert!(offset < 1024 * 1024 * 1024, "GPA 0x{gpa:x} outside RAM");
        unsafe { self.ram_host.add(offset) }
    }
}

/// Per-queue snapshots — set once at QUEUE_READY, immutable after.
static QUEUE_SNAPS: [OnceLock<QueueSnapshot>; MAX_QUEUES] = {
    // OnceLock::new() is const, but array-init requires a const block
    const INIT: OnceLock<QueueSnapshot> = OnceLock::new();
    [INIT; MAX_QUEUES]
};

pub fn queue_snapshot(index: usize) -> QueueSnapshot {
    if index < MAX_QUEUES {
        QUEUE_SNAPS[index]
            .get()
            .copied()
            .unwrap_or(QueueSnapshot::EMPTY)
    } else {
        QueueSnapshot::EMPTY
    }
}

/// Convenience alias for the single-queue-pair fallback path
/// (queue 0 = RX, queue 1 = TX when cpu_count == 1).
pub fn rx_queue_snapshot() -> QueueSnapshot {
    queue_snapshot(0)
}

impl VirtioNet {
    pub fn new(mac: [u8; 6], ram_host: *mut u8, ram_base: u64, cpu_count: usize) -> Self {
        let nqp = cpu_count.min(MAX_VCPUS) as u16;
        let num_queues = 2 * nqp as usize + 1; // 2*N pairs + ctrl VQ
        VirtioNet {
            status: 0,
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: [0; 2],
            queue_sel: 0,
            num_queues,
            queues: Default::default(),
            interrupt_status: 0,
            mac,
            ram_host,
            ram_base,
            used_idx: [0; MAX_QUEUES],
            num_queue_pairs: nqp,
        }
    }

    /// Handle a guest MMIO read.
    pub fn read(&mut self, offset: u64) -> u32 {
        match offset {
            MAGIC_VALUE => VIRTIO_MAGIC,
            VERSION => VIRTIO_VERSION_2,
            DEVICE_ID => VIRTIO_DEVICE_NET,
            VENDOR_ID => VIRTIO_VENDOR,
            DEVICE_FEATURES => {
                match self.device_features_sel {
                    // VIRTIO_NET_F_CSUM + VIRTIO_NET_F_HOST_TSO4 enable
                    // guest-side TSO: the guest hands us one super-segment
                    // (up to 64 KiB) with `gso_type=TCPV4` + `gso_size=MSS`
                    // and we forward the bytes to the host SOCK_STREAM.
                    // The host TCP stack handles segmentation transparently
                    // (we're a userspace TCP proxy, not a NIC), so the
                    // gso fields are advisory — but advertising them lets
                    // the guest collapse its per-MSS frame-build loop.
                    0 => {
                        VIRTIO_NET_F_CSUM
                            | VIRTIO_NET_F_MAC
                            | VIRTIO_NET_F_HOST_TSO4
                            | VIRTIO_NET_F_MQ
                            | VIRTIO_NET_F_CTRL_VQ
                    }
                    1 => 1, // VIRTIO_F_VERSION_1 (bit 0 of word 1 = feature bit 32)
                    _ => 0,
                }
            }
            QUEUE_NUM_MAX => QUEUE_SIZE,
            QUEUE_READY => {
                let qi = self.queue_sel as usize;
                if qi < self.num_queues {
                    self.queues[qi].ready as u32
                } else {
                    0
                }
            }
            STATUS => self.status,
            INTERRUPT_STATUS => {
                // SPI is edge-pulsed (assert+deassert) so it's already
                // low when the guest reads this. Just return and clear.
                let val = self.interrupt_status;
                self.interrupt_status = 0;
                val
            }
            // Device config: MAC[6] + status[2] + max_virtqueue_pairs[2]
            off if off >= CONFIG_BASE && off < CONFIG_BASE + 12 => {
                let cfg_off = (off - CONFIG_BASE) as usize;
                match cfg_off {
                    0..=3 => {
                        // MAC bytes 0..3
                        let mut val = 0u32;
                        for i in 0..4 {
                            if cfg_off + i < 6 {
                                val |= (self.mac[cfg_off + i] as u32) << (i * 8);
                            }
                        }
                        val
                    }
                    4..=7 => {
                        // MAC bytes 4..5 + status[2]
                        let mut val = 0u32;
                        for i in 0..4 {
                            if cfg_off + i < 6 {
                                val |= (self.mac[cfg_off + i] as u32) << (i * 8);
                            }
                        }
                        val
                    }
                    8..=11 => {
                        // max_virtqueue_pairs (u16 LE at offset 8)
                        self.num_queue_pairs as u32
                    }
                    _ => 0,
                }
            }
            // Device config: per-queue used_idx at offset 0x110 (RX=q0), 0x114 (TX=q1)
            // Returns used_idx[0] | (used_idx[1] << 16) as a single 32-bit read.
            // Guest reads this via MMIO to bypass dcache coherency issues.
            0x110 => self.used_idx[0] as u32 | ((self.used_idx[1] as u32) << 16),
            _ => 0,
        }
    }

    /// Handle a guest MMIO write. Returns true if a QUEUE_NOTIFY was written.
    pub fn write(&mut self, offset: u64, value: u32) -> bool {
        match offset {
            DEVICE_FEATURES_SEL => self.device_features_sel = value,
            DRIVER_FEATURES_SEL => self.driver_features_sel = value,
            DRIVER_FEATURES => {
                let sel = self.driver_features_sel as usize;
                if sel < 2 {
                    self.driver_features[sel] = value;
                }
            }
            QUEUE_SEL => self.queue_sel = value,
            QUEUE_NUM => {
                let qi = self.queue_sel as usize;
                if qi < self.num_queues {
                    self.queues[qi].num = value;
                }
            }
            QUEUE_READY => {
                let qi = self.queue_sel as usize;
                if qi < self.num_queues {
                    self.queues[qi].ready = value != 0;
                    if value != 0 {
                        let q = &self.queues[qi];
                        let snap = QueueSnapshot {
                            ram_host: self.ram_host,
                            ram_base: self.ram_base,
                            desc_addr: q.desc_addr(),
                            avail_addr: q.avail_addr(),
                            used_addr: q.used_addr(),
                            qsize: q.num as u16,
                            ready: true,
                        };
                        // Set VIRTQ_USED_F_NO_NOTIFY on all RX queues
                        // (even-indexed: 0, 2, 4, ...).
                        if qi % 2 == 0 && qi < 2 * self.num_queue_pairs as usize {
                            unsafe {
                                let flags_ptr = snap.gpa_to_host(snap.used_addr) as *mut u16;
                                core::ptr::write_volatile(flags_ptr, 1);
                            }
                        }
                        let _ = QUEUE_SNAPS[qi].set(snap);
                    }
                }
            }
            QUEUE_DESC_LOW => {
                let qi = self.queue_sel as usize;
                if qi < self.num_queues {
                    self.queues[qi].desc_lo = value;
                }
            }
            QUEUE_DESC_HIGH => {
                let qi = self.queue_sel as usize;
                if qi < self.num_queues {
                    self.queues[qi].desc_hi = value;
                }
            }
            QUEUE_DRIVER_LOW => {
                let qi = self.queue_sel as usize;
                if qi < self.num_queues {
                    self.queues[qi].driver_lo = value;
                }
            }
            QUEUE_DRIVER_HIGH => {
                let qi = self.queue_sel as usize;
                if qi < self.num_queues {
                    self.queues[qi].driver_hi = value;
                }
            }
            QUEUE_DEVICE_LOW => {
                let qi = self.queue_sel as usize;
                if qi < self.num_queues {
                    self.queues[qi].device_lo = value;
                }
            }
            QUEUE_DEVICE_HIGH => {
                let qi = self.queue_sel as usize;
                if qi < self.num_queues {
                    self.queues[qi].device_hi = value;
                }
            }
            STATUS => {
                self.status = value;
                if value == 0 {
                    // Reset
                    self.driver_features = [0; 2];
                    self.queue_sel = 0;
                    self.interrupt_status = 0;
                    for q in &mut self.queues {
                        *q = Default::default();
                    }
                }
                // Auto-set FEATURES_OK when driver requests it
                if value & STATUS_FEATURES_OK != 0 {
                    self.status |= STATUS_FEATURES_OK;
                }
            }
            INTERRUPT_ACK => {
                self.interrupt_status &= !value;
                if self.interrupt_status == 0 {
                    unsafe {
                        crate::hvf::hv_gic_set_spi(35, false);
                    }
                }
            }
            QUEUE_NOTIFY => {
                // value = queue index being notified
                return true;
            }
            _ => {}
        }
        false
    }

    /// The ctrl queue index: 2 * num_queue_pairs.
    pub fn ctrl_queue_index(&self) -> usize {
        2 * self.num_queue_pairs as usize
    }
}

/// Handle a VIRTIO_NET_CTRL_MQ command on the control virtqueue.
/// Called from the vCPU thread on QUEUE_NOTIFY with the ctrl queue index.
pub fn handle_ctrl_queue() {
    let snap = queue_snapshot(ctrl_queue_index());
    if !snap.ready {
        return;
    }

    // Read avail_idx
    let avail_idx =
        unsafe { core::ptr::read_volatile(snap.gpa_to_host(snap.avail_addr + 2) as *const u16) };

    // We need to track our own last-seen avail index.
    // For the ctrl queue, we use used_idx from the device as our "last" tracker.
    let used_idx =
        unsafe { core::ptr::read_volatile(snap.gpa_to_host(snap.used_addr + 2) as *const u16) };
    if used_idx == avail_idx {
        return;
    }

    let mut last = used_idx;
    while last != avail_idx {
        let ring_idx = last & (snap.qsize - 1);
        let first_desc_idx = unsafe {
            core::ptr::read_volatile(
                snap.gpa_to_host(snap.avail_addr + 4 + ring_idx as u64 * 2) as *const u16
            )
        };

        // Walk the descriptor chain.
        // Descriptor layout: addr(8) + len(4) + flags(2) + next(2) = 16 bytes each.
        // Expected chain for CTRL_MQ_VQ_PAIRS_SET:
        //   desc 0: class(1) + cmd(1) + data(2) = 4 bytes (device-readable)
        //   desc 1: ack(1) byte (device-writable)
        //
        // But some guests split it into 3 descriptors:
        //   desc 0: class(1) + cmd(1) header
        //   desc 1: data(2) = num_pairs
        //   desc 2: ack(1) byte
        //
        // We handle both by reading all device-readable bytes concatenated,
        // then writing ack to the last (device-writable) descriptor.

        let mut cmd_bytes = [0u8; 8];
        let mut cmd_len = 0usize;
        let mut _ack_desc_idx = first_desc_idx;
        let mut total_len = 0u32;
        let mut desc_idx = first_desc_idx;

        loop {
            let dp = snap.gpa_to_host(snap.desc_addr + desc_idx as u64 * 16);
            let addr = unsafe { core::ptr::read_unaligned(dp as *const u64) };
            let len = unsafe { core::ptr::read_unaligned(dp.add(8) as *const u32) };
            let flags = unsafe { core::ptr::read_unaligned(dp.add(12) as *const u16) };
            let next = unsafe { core::ptr::read_unaligned(dp.add(14) as *const u16) };
            total_len += len;

            const VRING_DESC_F_NEXT: u16 = 1;
            const VRING_DESC_F_WRITE: u16 = 2;

            if flags & VRING_DESC_F_WRITE == 0 {
                // Device-readable: accumulate command bytes
                let copy = (len as usize).min(cmd_bytes.len() - cmd_len);
                if copy > 0 {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            snap.gpa_to_host(addr),
                            cmd_bytes.as_mut_ptr().add(cmd_len),
                            copy,
                        );
                    }
                    cmd_len += copy;
                }
            } else {
                // Device-writable: this is the ack descriptor
                _ack_desc_idx = desc_idx;
                // Write ack = 0 (VIRTIO_NET_OK)
                unsafe {
                    core::ptr::write_volatile(snap.gpa_to_host(addr), 0u8);
                }
            }

            if flags & VRING_DESC_F_NEXT != 0 {
                desc_idx = next;
            } else {
                break;
            }
        }

        // Parse the command: class(1) + cmd(1) + data
        if cmd_len >= 4 {
            let class = cmd_bytes[0];
            let cmd = cmd_bytes[1];
            let _num_pairs = u16::from_le_bytes([cmd_bytes[2], cmd_bytes[3]]);
            if class == 4 && cmd == 0 {
                // VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET — ack already written
                eprintln!("  virtio: ctrl MQ set pairs = {_num_pairs}");
            }
        }

        // Update used ring
        unsafe {
            let entry = snap.gpa_to_host(snap.used_addr + 4 + (last & (snap.qsize - 1)) as u64 * 8);
            core::ptr::write_unaligned(entry as *mut u32, first_desc_idx as u32);
            core::ptr::write_unaligned(entry.add(4) as *mut u32, total_len);
            core::ptr::write_volatile(
                snap.gpa_to_host(snap.used_addr + 2) as *mut u16,
                last.wrapping_add(1),
            );
        }
        last = last.wrapping_add(1);
    }

    // Assert SPI to notify guest of ctrl completion.
    unsafe {
        core::arch::asm!("dsb sy", options(nostack));
        crate::hvf::hv_gic_set_spi(35, true);
        crate::hvf::hv_gic_set_spi(35, false);
    }
}

/// Get the ctrl queue index from the device.
pub fn ctrl_queue_index() -> usize {
    let dev = DEVICE.lock().unwrap();
    match dev.as_ref() {
        Some(d) => d.ctrl_queue_index(),
        None => 0,
    }
}
