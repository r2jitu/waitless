// tools/hvf-runner/src/virtio.rs
//
// Virtio-MMIO device emulation for virtio-net.
//
// Implements the register file at a single MMIO address (0x0a000000).
// The kernel's virtio_net::init_mmio() probes this device, negotiates
// features, sets up queues (RX=0, TX=1), and drives it via QUEUE_NOTIFY.
//
// This module handles the config-space interaction only. The actual
// packet I/O (reading/writing virtqueue descriptors, interfacing with
// vmnet) will be added when vmnet.rs is wired up.

use std::sync::Mutex;

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
const VIRTIO_NET_F_MAC: u32 = 1 << 5;

// Status bits
const STATUS_FEATURES_OK: u32 = 8;

const QUEUE_SIZE: u32 = 256;
const NUM_QUEUES: usize = 2; // RX=0, TX=1

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
    queues: [QueueState; NUM_QUEUES],
    pub interrupt_status: u32,
    mac: [u8; 6],
    /// Host pointer to the start of guest RAM (for translating GPAs to host).
    ram_host: *mut u8,
    ram_base: u64,
    /// Current used_idx for each queue, updated by check_rx/process_tx.
    /// Read by the guest via device config at offset 0x110+queue*2
    /// to bypass dcache coherency issues on HVF.
    pub used_idx: [u16; NUM_QUEUES],
}

// SAFETY: ram_host is a stable mapping for the VM's lifetime; only one
// thread (the vCPU) accesses VirtioNet during MMIO dispatch.
unsafe impl Send for VirtioNet {}

pub static DEVICE: Mutex<Option<VirtioNet>> = Mutex::new(None);

impl VirtioNet {
    pub fn new(mac: [u8; 6], ram_host: *mut u8, ram_base: u64) -> Self {
        VirtioNet {
            status: 0,
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: [0; 2],
            queue_sel: 0,
            queues: Default::default(),
            interrupt_status: 0,
            mac,
            ram_host,
            ram_base,
            used_idx: [0; NUM_QUEUES],
        }
    }

    /// Handle a guest MMIO read.
    pub fn read(&self, offset: u64) -> u32 {
        match offset {
            MAGIC_VALUE => VIRTIO_MAGIC,
            VERSION => VIRTIO_VERSION_2,
            DEVICE_ID => VIRTIO_DEVICE_NET,
            VENDOR_ID => VIRTIO_VENDOR,
            DEVICE_FEATURES => {
                match self.device_features_sel {
                    0 => VIRTIO_NET_F_MAC,
                    1 => 1, // VIRTIO_F_VERSION_1 (bit 0 of word 1 = feature bit 32)
                    _ => 0,
                }
            }
            QUEUE_NUM_MAX => QUEUE_SIZE,
            QUEUE_READY => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES { self.queues[qi].ready as u32 } else { 0 }
            }
            STATUS => self.status,
            INTERRUPT_STATUS => self.interrupt_status,
            // Device config: MAC address at offset 0x100..0x105
            off if off >= CONFIG_BASE && off < CONFIG_BASE + 8 => {
                let cfg_off = (off - CONFIG_BASE) as usize;
                let mut val = 0u32;
                for i in 0..4 {
                    if cfg_off + i < 6 {
                        val |= (self.mac[cfg_off + i] as u32) << (i * 8);
                    }
                }
                val
            }
            // Device config: per-queue used_idx at offset 0x110 (RX=q0), 0x114 (TX=q1)
            // Returns used_idx[0] | (used_idx[1] << 16) as a single 32-bit read.
            // Guest reads this via MMIO to bypass dcache coherency issues.
            0x110 => {
                self.used_idx[0] as u32 | ((self.used_idx[1] as u32) << 16)
            }
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
                if sel < 2 { self.driver_features[sel] = value; }
            }
            QUEUE_SEL => self.queue_sel = value,
            QUEUE_NUM => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES { self.queues[qi].num = value; }
            }
            QUEUE_READY => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES { self.queues[qi].ready = value != 0; }
            }
            QUEUE_DESC_LOW => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES { self.queues[qi].desc_lo = value; }
            }
            QUEUE_DESC_HIGH => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES { self.queues[qi].desc_hi = value; }
            }
            QUEUE_DRIVER_LOW => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES { self.queues[qi].driver_lo = value; }
            }
            QUEUE_DRIVER_HIGH => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES { self.queues[qi].driver_hi = value; }
            }
            QUEUE_DEVICE_LOW => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES { self.queues[qi].device_lo = value; }
            }
            QUEUE_DEVICE_HIGH => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES { self.queues[qi].device_hi = value; }
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
                // Deassert the SPI when all interrupt bits are cleared.
                // SPI 35 is level-triggered — if we don't deassert it,
                // the GIC re-fires the IRQ immediately after EOI and the
                // kernel gets stuck in an infinite interrupt loop.
                if self.interrupt_status == 0 {
                    unsafe { crate::hvf::hv_gic_set_spi(35, false); }
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

    /// Translate a guest physical address to a host pointer.
    pub unsafe fn gpa_to_host(&self, gpa: u64) -> *mut u8 {
        self.ram_host.add((gpa - self.ram_base) as usize)
    }

    /// Get a reference to a queue's state.
    pub fn queue(&self, index: usize) -> &QueueState {
        &self.queues[index]
    }
}
