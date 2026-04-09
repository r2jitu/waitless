// drivers/virtio_console.rs — VirtIO console device for VZ.framework and QEMU

use core::arch::asm;
use core::ptr;

use crate::{
    dsb_st, dsb_sy,
    mmio_read32, mmio_write32,
    vz_config_delay, vz_init_delay,
};
use crate::virtio::{
    vpci_find, vpci_reset, vpci_set_status, vpci_get_status,
    vpci_write_features, vpci_select_queue, vpci_get_queue_size,
    vpci_get_queue_notify_off, vpci_queue_notify_addr,
    vpci_set_queue_addrs, vpci_enable_queue,
    VPCI_DEVICES,
    STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FEATURES_OK, STATUS_FAILED,
    VIRTQ_DESC_F_WRITE,
    MMIO_MAGIC_VALUE, MMIO_VERSION, MMIO_DEVICE_ID,
    MMIO_STATUS, MMIO_MAGIC,
    MMIO_DRIVER_FEATURES_SEL, MMIO_GUEST_FEATURES, MMIO_GUEST_PAGE_SIZE,
    MMIO_QUEUE_SEL, MMIO_QUEUE_NUM_MAX, MMIO_QUEUE_NUM,
    MMIO_QUEUE_ALIGN, MMIO_QUEUE_PFN, MMIO_QUEUE_READY, MMIO_QUEUE_NOTIFY,
    MMIO_QUEUE_DESC_LOW, MMIO_QUEUE_DESC_HIGH,
    MMIO_QUEUE_DRIVER_LOW, MMIO_QUEUE_DRIVER_HIGH,
    MMIO_QUEUE_DEVICE_LOW, MMIO_QUEUE_DEVICE_HIGH,
};

// ============================================================================
// VirtIO console driver (DeviceID=3)
//
// Uses static BSS memory for ring buffers so it can init before mm::init().
// Two queues: RX (queue 0) = host->guest, TX (queue 1) = guest->host.
// ============================================================================

const CON_QS: usize = 16;
const CON_AVAIL_OFF: usize = CON_QS * 16; // 256
const CON_USED_OFF: usize = 4096;

// Static ring memory (page-aligned, in BSS)
#[repr(C, align(4096))]
struct ConQueueMem([u8; 8192]);

static mut CON_TX_MEM: ConQueueMem = ConQueueMem([0; 8192]);
static mut CON_RX_MEM: ConQueueMem = ConQueueMem([0; 8192]);

static mut CON_TX_BUF: [u8; 1] = [0];
static mut CON_RX_BUFS: [u8; CON_QS] = [0; CON_QS];

static mut CON_BASE: u64 = 0; // non-zero = initialized
static mut CON_PCI_MODE: bool = false;
static mut CON_TX_NOTIFY: u64 = 0;
static mut CON_RX_NOTIFY: u64 = 0;
static mut CON_TX_AVAIL_IDX: u16 = 0;
static mut CON_TX_LAST_USED: u16 = 0;
static mut CON_RX_AVAIL_IDX: u16 = 0;
static mut CON_RX_LAST_USED: u16 = 0;


// Ring accessors using raw pointer arithmetic

unsafe fn con_desc_addr(mem: &mut ConQueueMem, i: usize) -> *mut u64 {
    unsafe { mem.0.as_mut_ptr().add(i * 16) as *mut u64 }
}
unsafe fn con_desc_len(mem: &mut ConQueueMem, i: usize) -> *mut u32 {
    unsafe { mem.0.as_mut_ptr().add(i * 16 + 8) as *mut u32 }
}
unsafe fn con_desc_flags(mem: &mut ConQueueMem, i: usize) -> *mut u16 {
    unsafe { mem.0.as_mut_ptr().add(i * 16 + 12) as *mut u16 }
}
unsafe fn con_avail_idx_reg(mem: &mut ConQueueMem) -> *mut u16 {
    unsafe { mem.0.as_mut_ptr().add(CON_AVAIL_OFF + 2) as *mut u16 }
}
unsafe fn con_avail_ring(mem: &mut ConQueueMem, i: usize) -> *mut u16 {
    unsafe { mem.0.as_mut_ptr().add(CON_AVAIL_OFF + 4 + i * 2) as *mut u16 }
}
unsafe fn con_used_idx_reg(mem: &ConQueueMem) -> *const u16 {
    unsafe { mem.0.as_ptr().add(CON_USED_OFF + 2) as *const u16 }
}
unsafe fn con_used_ring_id(mem: &ConQueueMem, i: usize) -> *const u32 {
    unsafe { mem.0.as_ptr().add(CON_USED_OFF + 4 + i * 8) as *const u32 }
}

// ---- MMIO console init -------------------------------------------------------

fn con_init_mmio_queue(base: u64, qidx: u32, mem: &mut ConQueueMem, is_v2: bool) -> bool {
    unsafe {
        mmio_write32(base + MMIO_QUEUE_SEL, qidx);
        let qmax = mmio_read32(base + MMIO_QUEUE_NUM_MAX);
        if qmax == 0 { return false; }
        let qs = if (CON_QS as u32) < qmax { CON_QS as u32 } else { qmax };
        mmio_write32(base + MMIO_QUEUE_NUM, qs);

        if is_v2 {
            let desc_addr = mem.0.as_ptr() as u64;
            let avail_addr = desc_addr + CON_AVAIL_OFF as u64;
            let used_addr = desc_addr + CON_USED_OFF as u64;
            mmio_write32(base + MMIO_QUEUE_DESC_LOW, desc_addr as u32);
            mmio_write32(base + MMIO_QUEUE_DESC_HIGH, (desc_addr >> 32) as u32);
            mmio_write32(base + MMIO_QUEUE_DRIVER_LOW, avail_addr as u32);
            mmio_write32(base + MMIO_QUEUE_DRIVER_HIGH, (avail_addr >> 32) as u32);
            mmio_write32(base + MMIO_QUEUE_DEVICE_LOW, used_addr as u32);
            mmio_write32(base + MMIO_QUEUE_DEVICE_HIGH, (used_addr >> 32) as u32);
            mmio_write32(base + MMIO_QUEUE_READY, 1);
        } else {
            mmio_write32(base + MMIO_QUEUE_ALIGN, 4096);
            mmio_write32(base + MMIO_QUEUE_PFN, (mem.0.as_ptr() as u64 >> 12) as u32);
        }
    }
    true
}

fn con_init_mmio(base_addr: u64) -> bool {
    unsafe {
        if mmio_read32(base_addr + MMIO_MAGIC_VALUE) != MMIO_MAGIC { return false; }
        let ver = mmio_read32(base_addr + MMIO_VERSION);
        if ver != 1 && ver != 2 { return false; }
        if mmio_read32(base_addr + MMIO_DEVICE_ID) != 3 { return false; }

        let is_v2 = ver == 2;

        // Reset -> ACKNOWLEDGE -> DRIVER
        mmio_write32(base_addr + MMIO_STATUS, 0);
        mmio_write32(base_addr + MMIO_STATUS, STATUS_ACKNOWLEDGE as u32);
        mmio_write32(base_addr + MMIO_STATUS, (STATUS_ACKNOWLEDGE | STATUS_DRIVER) as u32);

        if is_v2 {
            mmio_write32(base_addr + MMIO_DRIVER_FEATURES_SEL, 0);
            mmio_write32(base_addr + MMIO_GUEST_FEATURES, 0);
            mmio_write32(base_addr + MMIO_DRIVER_FEATURES_SEL, 1);
            mmio_write32(base_addr + MMIO_GUEST_FEATURES, 0);
            mmio_write32(base_addr + MMIO_STATUS,
                         (STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK) as u32);
            if (mmio_read32(base_addr + MMIO_STATUS) & STATUS_FEATURES_OK as u32) == 0 {
                mmio_write32(base_addr + MMIO_STATUS, STATUS_FAILED as u32);
                return false;
            }
        } else {
            mmio_write32(base_addr + MMIO_GUEST_FEATURES, 0);
            mmio_write32(base_addr + MMIO_GUEST_PAGE_SIZE, 4096);
        }

        // Zero ring memory
        ptr::write_bytes(CON_RX_MEM.0.as_mut_ptr(), 0, 8192);
        ptr::write_bytes(CON_TX_MEM.0.as_mut_ptr(), 0, 8192);

        if !con_init_mmio_queue(base_addr, 0, &mut CON_RX_MEM, is_v2) { return false; }
        if !con_init_mmio_queue(base_addr, 1, &mut CON_TX_MEM, is_v2) { return false; }

        // Pre-populate RX descriptors
        for i in 0..CON_QS {
            ptr::write_volatile(con_desc_addr(&mut CON_RX_MEM, i),
                                CON_RX_BUFS.as_ptr().add(i) as u64);
            ptr::write_volatile(con_desc_len(&mut CON_RX_MEM, i), 1);
            ptr::write_volatile(con_desc_flags(&mut CON_RX_MEM, i), VIRTQ_DESC_F_WRITE);
            ptr::write_volatile(con_avail_ring(&mut CON_RX_MEM, i), i as u16);
            CON_RX_AVAIL_IDX += 1;
        }
        dsb_st();
        ptr::write_volatile(con_avail_idx_reg(&mut CON_RX_MEM), CON_RX_AVAIL_IDX);
        dsb_sy();
        mmio_write32(base_addr + MMIO_QUEUE_NOTIFY, 0);

        // TX descriptor 0
        ptr::write_volatile(con_desc_addr(&mut CON_TX_MEM, 0), CON_TX_BUF.as_ptr() as u64);
        ptr::write_volatile(con_desc_len(&mut CON_TX_MEM, 0), 1);
        ptr::write_volatile(con_desc_flags(&mut CON_TX_MEM, 0), 0);

        let mut final_status = (STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK) as u32;
        if is_v2 { final_status |= STATUS_FEATURES_OK as u32; }
        mmio_write32(base_addr + MMIO_STATUS, final_status);

        CON_BASE = base_addr;
        CON_PCI_MODE = false;
    }
    true
}

// ---- PCI console init (VZ.framework) -----------------------------------------

fn con_init_pci() -> bool {
    // Find console device (type 3) using Rust PCI infrastructure
    let vpci_idx = match vpci_find(3) {
        Some(i) => i,
        None => return false,
    };

    let dev = unsafe { &VPCI_DEVICES[vpci_idx] };

    vpci_reset(dev);
    vz_config_delay();
    vpci_set_status(dev, STATUS_ACKNOWLEDGE);
    vz_config_delay();
    vpci_set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
    vz_config_delay();

    vpci_write_features(dev, 0, 0);
    vpci_write_features(dev, 1, 1); // VIRTIO_F_VERSION_1
    vz_config_delay();
    vpci_set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
    vz_config_delay();
    if (vpci_get_status(dev) & STATUS_FEATURES_OK) == 0 {
        vpci_set_status(dev, STATUS_FAILED);
        return false;
    }

    unsafe {
        ptr::write_bytes(CON_RX_MEM.0.as_mut_ptr(), 0, 8192);
        ptr::write_bytes(CON_TX_MEM.0.as_mut_ptr(), 0, 8192);
    }

    // Init RX queue (0)
    vpci_select_queue(dev, 0);
    let qmax = vpci_get_queue_size(dev);
    if qmax == 0 { return false; }
    unsafe {
        let desc_addr = CON_RX_MEM.0.as_ptr() as u64;
        let avail_addr = desc_addr + CON_AVAIL_OFF as u64;
        let used_addr = desc_addr + CON_USED_OFF as u64;
        vpci_set_queue_addrs(dev, desc_addr, avail_addr, used_addr);
        vpci_enable_queue(dev);
    }

    // Init TX queue (1)
    vpci_select_queue(dev, 1);
    let qmax_tx = vpci_get_queue_size(dev);
    if qmax_tx == 0 { return false; }
    unsafe {
        let desc_addr = CON_TX_MEM.0.as_ptr() as u64;
        let avail_addr = desc_addr + CON_AVAIL_OFF as u64;
        let used_addr = desc_addr + CON_USED_OFF as u64;
        vpci_set_queue_addrs(dev, desc_addr, avail_addr, used_addr);
        vpci_enable_queue(dev);
    }

    // Get notify addresses
    vpci_select_queue(dev, 0);
    let rx_noff = vpci_get_queue_notify_off(dev);
    let rx_notify = vpci_queue_notify_addr(dev, rx_noff);

    vpci_select_queue(dev, 1);
    let tx_noff = vpci_get_queue_notify_off(dev);
    let tx_notify = vpci_queue_notify_addr(dev, tx_noff);

    // Pre-populate RX descriptors
    unsafe {
        for i in 0..CON_QS {
            ptr::write_volatile(con_desc_addr(&mut CON_RX_MEM, i),
                                CON_RX_BUFS.as_ptr().add(i) as u64);
            ptr::write_volatile(con_desc_len(&mut CON_RX_MEM, i), 1);
            ptr::write_volatile(con_desc_flags(&mut CON_RX_MEM, i), VIRTQ_DESC_F_WRITE);
            ptr::write_volatile(con_avail_ring(&mut CON_RX_MEM, i), i as u16);
            CON_RX_AVAIL_IDX += 1;
        }
        dsb_st();
        ptr::write_volatile(con_avail_idx_reg(&mut CON_RX_MEM), CON_RX_AVAIL_IDX);
        dsb_sy();

        // TX descriptor 0
        ptr::write_volatile(con_desc_addr(&mut CON_TX_MEM, 0), CON_TX_BUF.as_ptr() as u64);
        ptr::write_volatile(con_desc_len(&mut CON_TX_MEM, 0), 1);
        ptr::write_volatile(con_desc_flags(&mut CON_TX_MEM, 0), 0);
    }

    // DRIVER_OK
    vpci_set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER |
                         STATUS_FEATURES_OK | STATUS_DRIVER_OK);

    // Kick RX queue
    unsafe { ptr::write_volatile(rx_notify as *mut u16, 0); }

    vz_init_delay(); // VZ needs time after DRIVER_OK

    unsafe {
        CON_BASE = 1; // sentinel
        CON_PCI_MODE = true;
        CON_TX_NOTIFY = tx_notify;
        CON_RX_NOTIFY = rx_notify;
    }
    true
}

// ---- Console I/O ------------------------------------------------------------

fn con_putc(c: u8) {
    unsafe {
        if CON_BASE == 0 { return; }

        // Spin until previous TX completes
        while CON_TX_LAST_USED < CON_TX_AVAIL_IDX {
            let u = ptr::read_volatile(con_used_idx_reg(&CON_TX_MEM));
            if u != CON_TX_LAST_USED { CON_TX_LAST_USED = u; }
            #[cfg(target_arch = "aarch64")]
            asm!("yield", options(nostack, preserves_flags));
            #[cfg(target_arch = "x86_64")]
            asm!("pause", options(nostack, preserves_flags));
        }

        CON_TX_BUF[0] = c;

        dsb_st();
        let slot = (CON_TX_AVAIL_IDX % CON_QS as u16) as usize;
        ptr::write_volatile(con_avail_ring(&mut CON_TX_MEM, slot), 0);
        dsb_st();
        ptr::write_volatile(con_avail_idx_reg(&mut CON_TX_MEM), CON_TX_AVAIL_IDX + 1);
        CON_TX_AVAIL_IDX += 1;
        dsb_sy();

        // Kick TX queue
        if CON_PCI_MODE {
            ptr::write_volatile(CON_TX_NOTIFY as *mut u16, 1);
        } else {
            mmio_write32(CON_BASE + MMIO_QUEUE_NOTIFY, 1);
        }

        // Spin until TX completes
        while ptr::read_volatile(con_used_idx_reg(&CON_TX_MEM)) == CON_TX_LAST_USED {
            #[cfg(target_arch = "aarch64")]
            asm!("yield", options(nostack, preserves_flags));
            #[cfg(target_arch = "x86_64")]
            asm!("pause", options(nostack, preserves_flags));
        }
        CON_TX_LAST_USED = ptr::read_volatile(con_used_idx_reg(&CON_TX_MEM));
    }
}

fn con_try_getc() -> i32 {
    unsafe {
        if CON_BASE == 0 { return -1; }

        let used_idx = ptr::read_volatile(con_used_idx_reg(&CON_RX_MEM));
        if used_idx == CON_RX_LAST_USED { return -1; }

        let slot = (CON_RX_LAST_USED % CON_QS as u16) as usize;
        let desc_id = ptr::read_volatile(con_used_ring_id(&CON_RX_MEM, slot)) as usize;
        let c = CON_RX_BUFS[desc_id] as i32;
        CON_RX_LAST_USED += 1;

        // Resubmit descriptor
        ptr::write_volatile(con_desc_addr(&mut CON_RX_MEM, desc_id),
                            CON_RX_BUFS.as_ptr().add(desc_id) as u64);
        ptr::write_volatile(con_desc_len(&mut CON_RX_MEM, desc_id), 1);
        ptr::write_volatile(con_desc_flags(&mut CON_RX_MEM, desc_id), VIRTQ_DESC_F_WRITE);

        dsb_st();
        let avail_slot = (CON_RX_AVAIL_IDX % CON_QS as u16) as usize;
        ptr::write_volatile(con_avail_ring(&mut CON_RX_MEM, avail_slot), desc_id as u16);
        dsb_st();
        ptr::write_volatile(con_avail_idx_reg(&mut CON_RX_MEM), CON_RX_AVAIL_IDX + 1);
        CON_RX_AVAIL_IDX += 1;
        dsb_sy();

        // Kick RX queue
        if CON_PCI_MODE {
            ptr::write_volatile(CON_RX_NOTIFY as *mut u16, 0);
        } else {
            mmio_write32(CON_BASE + MMIO_QUEUE_NOTIFY, 0);
        }

        c
    }
}

// ============================================================================
// Public API — VirtIO console
//
// NOTE: These functions are also called from kernel/serial.rs via FFI
// (serial cannot depend on drivers due to circular dependency).
// Keep #[unsafe(no_mangle)] + extern "C" for FFI linkage.
// ============================================================================

/// Initialize console via virtio-mmio at given base address.
/// Returns true if device found and initialized.
#[unsafe(no_mangle)]
pub extern "C" fn virtio_console_init_mmio(base_addr: u64) -> bool {
    con_init_mmio(base_addr)
}

/// Initialize console via PCI (scans PCI bus, finds device type 3).
/// PCI must be initialized first (pci::init).
#[unsafe(no_mangle)]
pub extern "C" fn virtio_console_init_pci() -> bool {
    con_init_pci()
}

/// Write one byte to the console.
#[unsafe(no_mangle)]
pub extern "C" fn virtio_console_putc(c: u8) {
    con_putc(c);
}

/// Try to read one byte from the console. Returns -1 if nothing available.
#[unsafe(no_mangle)]
pub extern "C" fn virtio_console_try_getc() -> i32 {
    con_try_getc()
}
