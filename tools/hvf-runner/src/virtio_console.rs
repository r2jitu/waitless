// tools/hvf-runner/src/virtio_console.rs
//
// Virtio-MMIO console device emulation (DeviceID = 3).
//
// The kernel's `drivers/virtio_console.rs` driver init scans the
// FDT's virtio-mmio devices, picks the one with DeviceID=3, and
// drives a 16-entry single-byte TX/RX queue pair. This file
// emulates that device on the host side: TX descriptors → stdout,
// stdin bytes → RX descriptors.
//
// Why this replaces the runner's PL011: under HVF, the previous
// PL011 path used a non-standard "8 bytes per MMIO write to DR"
// trick — fast (~5× boot logging speedup) but specific to this
// runner. Virtio-console gives the same boot binary one console
// transport across HVF / KVM-virtio / future paravirt platforms,
// at the cost of slightly more host code. QEMU TCG aarch64 keeps
// PL011 because its `-machine virt` FDT advertises one — the
// kernel's `serial::aarch64::init` falls through to virtio-mmio
// only when the FDT has no `uart_base`.
//
// ── SAFETY ────────────────────────────────────────────────────
// Same model as virtio.rs: guest RAM is mapped once via
// `hv_vm_map` for the VM lifetime, and `gpa_to_host` translates a
// guest physical address into a host pointer inside that mapping.
// Descriptor reads / used-ring writes go through that translation;
// guest descriptor lengths are bounded by the queue size we
// publish (16) and the byte counts we accept on each path.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::Mutex;

// ── Virtio-MMIO register offsets (must match kernel's drivers/virtio.rs) ─

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

const VIRTIO_MAGIC: u32 = 0x7472_6976;
const VIRTIO_VERSION_2: u32 = 2;
const VIRTIO_DEVICE_CONSOLE: u32 = 3;
const VIRTIO_VENDOR: u32 = 0x554d_4551; // "QEMU"

const STATUS_FEATURES_OK: u32 = 8;

const QUEUE_SIZE_MAX: u32 = 16; // kernel uses CON_QS=16
const RX_QUEUE: usize = 0;
const TX_QUEUE: usize = 1;
const NUM_QUEUES: usize = 2;

const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

/// Stdin → guest RX buffer. Fed by the stdin reader thread in
/// `main.rs`; drained by `process_rx` from the vCPU poll loop.
pub static RX_BUF: Mutex<VecDeque<u8>> = Mutex::new(VecDeque::new());

/// True if the stdin path has data the guest hasn't consumed yet.
/// Used by the cooperative-yield loop in `vm.rs` to break out of a
/// parked vCPU so Ctrl-C reaches the guest's serial RX path.
pub fn rx_has_data() -> bool {
    !RX_BUF.lock().unwrap().is_empty()
}

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
    /// Driver-private cursor: the next avail-ring slot we will read.
    /// Advances as we pull entries out and write the matching used-
    /// ring entries.
    last_avail: u16,
    /// Our copy of used_idx — keeps a running counter so we don't
    /// have to read it back from guest memory on every TX.
    used_idx: u16,
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

pub struct VirtioConsole {
    status: u32,
    device_features_sel: u32,
    driver_features_sel: u32,
    driver_features: [u32; 2],
    queue_sel: u32,
    queues: [QueueState; NUM_QUEUES],
    pub interrupt_status: u32,
    /// Host pointer to start of guest RAM (for GPA → host translation).
    ram_host: *mut u8,
    ram_base: u64,
    /// Buffered TX bytes, flushed in chunks. Newline triggers an
    /// immediate flush so log lines appear as written; otherwise we
    /// flush at 256 bytes to amortise the syscall.
    tx_pending: Vec<u8>,
}

// SAFETY: ram_host is a stable mapping for the VM's lifetime; only
// one thread (the vCPU) accesses VirtioConsole during MMIO dispatch
// or RX injection.
unsafe impl Send for VirtioConsole {}

pub static DEVICE: Mutex<Option<VirtioConsole>> = Mutex::new(None);

impl VirtioConsole {
    pub fn new(ram_host: *mut u8, ram_base: u64) -> Self {
        VirtioConsole {
            status: 0,
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: [0; 2],
            queue_sel: 0,
            queues: Default::default(),
            interrupt_status: 0,
            ram_host,
            ram_base,
            tx_pending: Vec::with_capacity(256),
        }
    }

    fn gpa_to_host(&self, gpa: u64) -> *mut u8 {
        let offset = gpa.wrapping_sub(self.ram_base) as usize;
        debug_assert!(offset < 1024 * 1024 * 1024, "GPA 0x{gpa:x} outside RAM");
        unsafe { self.ram_host.add(offset) }
    }

    /// Handle a guest MMIO read.
    pub fn read(&mut self, offset: u64) -> u32 {
        match offset {
            MAGIC_VALUE => VIRTIO_MAGIC,
            VERSION => VIRTIO_VERSION_2,
            DEVICE_ID => VIRTIO_DEVICE_CONSOLE,
            VENDOR_ID => VIRTIO_VENDOR,
            DEVICE_FEATURES => {
                match self.device_features_sel {
                    // Word 0: no console-specific features. The kernel
                    // driver writes 0 anyway (no SIZE / MULTIPORT /
                    // EMERG_WRITE), so don't offer any.
                    0 => 0,
                    // Word 1: VIRTIO_F_VERSION_1 (bit 32 = bit 0 of word 1).
                    // Required for v2 transport.
                    1 => 1,
                    _ => 0,
                }
            }
            QUEUE_NUM_MAX => QUEUE_SIZE_MAX,
            QUEUE_READY => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    self.queues[qi].ready as u32
                } else {
                    0
                }
            }
            STATUS => self.status,
            INTERRUPT_STATUS => {
                // No IRQ delivery for console — the kernel polls
                // used_idx for both TX completion and RX arrival.
                // Returning 0 / no-op on ack matches that contract.
                let val = self.interrupt_status;
                self.interrupt_status = 0;
                val
            }
            // Console config space: (cols, rows, max_nr_ports, emerg_wr).
            // The driver doesn't read it; return 0 for simplicity.
            _ => 0,
        }
    }

    /// Handle a guest MMIO write. Returns true if a QUEUE_NOTIFY was
    /// written (caller should drive the corresponding queue).
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
                if qi < NUM_QUEUES {
                    self.queues[qi].num = value;
                }
            }
            QUEUE_READY => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    self.queues[qi].ready = value != 0;
                }
            }
            QUEUE_DESC_LOW => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    self.queues[qi].desc_lo = value;
                }
            }
            QUEUE_DESC_HIGH => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    self.queues[qi].desc_hi = value;
                }
            }
            QUEUE_DRIVER_LOW => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    self.queues[qi].driver_lo = value;
                }
            }
            QUEUE_DRIVER_HIGH => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    self.queues[qi].driver_hi = value;
                }
            }
            QUEUE_DEVICE_LOW => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    self.queues[qi].device_lo = value;
                }
            }
            QUEUE_DEVICE_HIGH => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    self.queues[qi].device_hi = value;
                }
            }
            STATUS => {
                self.status = value;
                if value == 0 {
                    self.driver_features = [0; 2];
                    self.queue_sel = 0;
                    self.interrupt_status = 0;
                    for q in &mut self.queues {
                        *q = Default::default();
                    }
                }
                if value & STATUS_FEATURES_OK != 0 {
                    self.status |= STATUS_FEATURES_OK;
                }
            }
            INTERRUPT_ACK => {
                self.interrupt_status &= !value;
            }
            QUEUE_NOTIFY => return true,
            _ => {}
        }
        false
    }

    /// Process every avail-ring entry on the TX queue, write each
    /// descriptor's bytes to stdout, and post matching used-ring
    /// entries. Called from the vCPU thread on QUEUE_NOTIFY for
    /// queue 1.
    fn process_tx(&mut self) {
        // Copy queue config out so we can mutate `self` (append_tx,
        // last_avail/used_idx updates) without aliasing a borrow of
        // self.queues.
        let q = &self.queues[TX_QUEUE];
        if !q.ready {
            return;
        }
        let qsize = q.num as u16;
        if qsize == 0 || (qsize & (qsize - 1)) != 0 {
            return;
        }
        let desc_addr = q.desc_addr();
        let avail_addr = q.avail_addr();
        let used_addr = q.used_addr();
        let mut last = q.last_avail;
        let mut used_idx = q.used_idx;

        let avail_idx =
            unsafe { std::ptr::read_volatile(self.gpa_to_host(avail_addr + 2) as *const u16) };

        while last != avail_idx {
            let ring_slot = last & (qsize - 1);
            let first_desc = unsafe {
                std::ptr::read_volatile(
                    self.gpa_to_host(avail_addr + 4 + ring_slot as u64 * 2) as *const u16
                )
            };

            // Walk the descriptor chain and emit each readable buffer.
            // The kernel driver currently chains only one descriptor
            // per byte, but a future batched-TX path may chain more —
            // honour the full chain.
            let mut total_len: u32 = 0;
            let mut desc_idx = first_desc;
            loop {
                let dp = self.gpa_to_host(desc_addr + desc_idx as u64 * 16);
                let addr = unsafe { std::ptr::read_unaligned(dp as *const u64) };
                let len = unsafe { std::ptr::read_unaligned(dp.add(8) as *const u32) };
                let flags = unsafe { std::ptr::read_unaligned(dp.add(12) as *const u16) };
                let next = unsafe { std::ptr::read_unaligned(dp.add(14) as *const u16) };

                if flags & VRING_DESC_F_WRITE == 0 && len > 0 {
                    let base = self.gpa_to_host(addr);
                    let bytes = unsafe { std::slice::from_raw_parts(base, len as usize) };
                    self.append_tx(bytes);
                }
                total_len += len;

                if flags & VRING_DESC_F_NEXT == 0 {
                    break;
                }
                desc_idx = next;
            }

            // used_ring entry at slot=used_idx (NOT last — used_idx
            // tracks our publication cursor); bump for next entry.
            let used_slot = used_idx & (qsize - 1);
            unsafe {
                let entry = self.gpa_to_host(used_addr + 4 + used_slot as u64 * 8);
                std::ptr::write_unaligned(entry as *mut u32, first_desc as u32);
                std::ptr::write_unaligned(entry.add(4) as *mut u32, total_len);
            }
            used_idx = used_idx.wrapping_add(1);
            last = last.wrapping_add(1);
        }

        let q = &mut self.queues[TX_QUEUE];
        if q.last_avail != last {
            q.last_avail = last;
            q.used_idx = used_idx;
            unsafe {
                std::ptr::write_volatile(self.gpa_to_host(used_addr + 2) as *mut u16, used_idx);
            }
        }

        // Flush any pending TX bytes immediately on QUEUE_NOTIFY —
        // even without a newline. The guest only kicks the queue when
        // it has something to send, so deferring further would just
        // delay output the user is already waiting on.
        self.flush_tx();
    }

    fn append_tx(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if b == 0 {
                continue;
            } // null-terminator from packed writes
            self.tx_pending.push(b);
            // Flush eagerly on newline for line-buffered console feel.
            // 256 bytes is the upper bound — anything bigger and we'd
            // be holding back output for too long.
            if b == b'\n' || self.tx_pending.len() >= 256 {
                self.flush_tx();
            }
        }
    }

    fn flush_tx(&mut self) {
        if self.tx_pending.is_empty() {
            return;
        }
        let _ = std::io::stdout().write_all(&self.tx_pending);
        let _ = std::io::stdout().flush();
        self.tx_pending.clear();
    }

    /// Drain any bytes from `RX_BUF` into guest RX descriptors.
    /// Called periodically from the vCPU poll cycle. Each available
    /// descriptor consumes one byte (matches the kernel driver's
    /// 16-entry × 1-byte RX layout); if the queue is full, leaves
    /// the bytes in `RX_BUF` for the next cycle.
    fn process_rx(&mut self) {
        let q = &self.queues[RX_QUEUE];
        if !q.ready {
            return;
        }
        let qsize = q.num as u16;
        if qsize == 0 || (qsize & (qsize - 1)) != 0 {
            return;
        }
        let desc_addr = q.desc_addr();
        let avail_addr = q.avail_addr();
        let used_addr = q.used_addr();
        let mut last = q.last_avail;
        let mut used_idx = q.used_idx;

        let mut buf = RX_BUF.lock().unwrap();
        if buf.is_empty() {
            return;
        }

        let avail_idx =
            unsafe { std::ptr::read_volatile(self.gpa_to_host(avail_addr + 2) as *const u16) };
        let mut pushed = 0;

        while last != avail_idx {
            let Some(byte) = buf.pop_front() else {
                break;
            };

            let ring_slot = last & (qsize - 1);
            let first_desc = unsafe {
                std::ptr::read_volatile(
                    self.gpa_to_host(avail_addr + 4 + ring_slot as u64 * 2) as *const u16
                )
            };

            // First (and only) descriptor in the chain is writable
            // and points at a 1-byte buffer in the kernel's rx_bufs.
            let dp = self.gpa_to_host(desc_addr + first_desc as u64 * 16);
            let addr = unsafe { std::ptr::read_unaligned(dp as *const u64) };
            unsafe {
                std::ptr::write_volatile(self.gpa_to_host(addr), byte);
            }

            let used_slot = used_idx & (qsize - 1);
            unsafe {
                let entry = self.gpa_to_host(used_addr + 4 + used_slot as u64 * 8);
                std::ptr::write_unaligned(entry as *mut u32, first_desc as u32);
                std::ptr::write_unaligned(entry.add(4) as *mut u32, 1u32);
            }
            used_idx = used_idx.wrapping_add(1);
            last = last.wrapping_add(1);
            pushed += 1;
        }

        if pushed > 0 {
            let q = &mut self.queues[RX_QUEUE];
            q.last_avail = last;
            q.used_idx = used_idx;
            unsafe {
                // dsb sy: rx_buf and used-ring entry writes must be
                // visible to the guest before it observes the bumped
                // used_idx (the guest's `con_try_getc` reads used_idx
                // first via `read_volatile` then dereferences the
                // payload without its own incoming barrier).
                core::arch::asm!("dsb sy", options(nostack));
                std::ptr::write_volatile(self.gpa_to_host(used_addr + 2) as *mut u16, used_idx);
                core::arch::asm!("dsb sy", options(nostack));
            }
        }
    }
}

/// Drive the TX queue (queue index 1). Called from the MMIO
/// dispatcher on QUEUE_NOTIFY for queue 1.
pub fn process_tx_queue() {
    if let Some(dev) = DEVICE.lock().unwrap().as_mut() {
        dev.process_tx();
    }
}

/// Drive the RX queue (queue index 0). Called periodically from
/// the vCPU poll loop and from the stdin reader after a new byte
/// lands in `RX_BUF`.
pub fn drive_rx() {
    if let Some(dev) = DEVICE.lock().unwrap().as_mut() {
        dev.process_rx();
    }
}
