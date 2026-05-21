// drivers/virtio-console/src/lib.rs — the `virtio_console` crate:
// the VirtIO console device driver (virtio DeviceID 3).
//
// A virtio device driver — peer of `virtio-net` / `gve` — split out
// of the `bus` crate so `bus` stays purely the shared bus/transport
// layer. `kernel_bare::serial` drives this through the `extern "C"`
// `virtio_console_*` symbols at the bottom of this file; a normal
// Rust dependency would cycle (console -> bus -> kernel_bare).

#![no_std]

use core::arch::asm;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicU16, Ordering};

use bus::virtio::{
    MMIO_DEVICE_ID, MMIO_DRIVER_FEATURES_SEL, MMIO_GUEST_FEATURES, MMIO_GUEST_PAGE_SIZE,
    MMIO_MAGIC, MMIO_MAGIC_VALUE, MMIO_QUEUE_ALIGN, MMIO_QUEUE_DESC_HIGH, MMIO_QUEUE_DESC_LOW,
    MMIO_QUEUE_DEVICE_HIGH, MMIO_QUEUE_DEVICE_LOW, MMIO_QUEUE_DRIVER_HIGH, MMIO_QUEUE_DRIVER_LOW,
    MMIO_QUEUE_NOTIFY, MMIO_QUEUE_NUM, MMIO_QUEUE_NUM_MAX, MMIO_QUEUE_PFN, MMIO_QUEUE_READY,
    MMIO_QUEUE_SEL, MMIO_STATUS, MMIO_VERSION, STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK,
    STATUS_FAILED, STATUS_FEATURES_OK, VIRTQ_DESC_F_WRITE, vpci_device, vpci_enable_queue,
    vpci_find, vpci_get_queue_notify_off, vpci_get_queue_size, vpci_get_status,
    vpci_queue_notify_addr, vpci_reset, vpci_select_queue, vpci_set_queue_addrs, vpci_set_status,
    vpci_write_features,
};
use bus::{dsb_st, dsb_sy, mmio_read32, mmio_write32};

// ============================================================================
// VirtIO console driver (DeviceID=3)
//
// Uses static BSS memory for ring buffers so it can init before mm::init().
// Two queues: RX (queue 0) = host->guest, TX (queue 1) = guest->host.
//
// State lives in one `UnsafeCell<VirtioConsole>` — `static mut` replaced
// with interior mutability and an `unsafe impl Sync`. Single-threaded by
// contract: `kernel_bare::serial` holds a spinlock around every `puts` /
// `putc` / `try_getc` call, so no concurrent mutation ever reaches us.
// ============================================================================

const CON_QS: usize = 16;
const CON_AVAIL_OFF: usize = CON_QS * 16; // 256
const CON_USED_OFF: usize = 4096;

/// TX payload buffer size. Sized so a typical kernel log line
/// (~80 chars) fits in one descriptor, so one MMIO QUEUE_NOTIFY +
/// one used-ring poll suffices per line. The HVF runner emulates
/// virtio-mmio entirely in-process; on KVM/QEMU each NOTIFY is one
/// vmexit. Either way, batching the whole line cuts vmexit count
/// from O(line length) to O(1).
const CON_TX_BUF_LEN: usize = 256;

// Queue-ring storage (page-aligned, in BSS).
#[repr(C, align(4096))]
struct ConQueueMem([u8; 8192]);

/// All driver state in one struct.
#[repr(C, align(4096))] // Alignment propagates from ConQueueMem.
struct VirtioConsole {
    tx_mem: ConQueueMem,
    rx_mem: ConQueueMem,
    tx_buf: [u8; CON_TX_BUF_LEN],
    rx_bufs: [u8; CON_QS],
    /// Non-zero = initialized. `1` is used as a sentinel on the PCI
    /// path (the real MMIO base doesn't apply there).
    base: u64,
    pci_mode: bool,
    tx_notify: u64,
    rx_notify: u64,
}

impl VirtioConsole {
    const fn new() -> Self {
        Self {
            tx_mem: ConQueueMem([0; 8192]),
            rx_mem: ConQueueMem([0; 8192]),
            tx_buf: [0; CON_TX_BUF_LEN],
            rx_bufs: [0; CON_QS],
            base: 0,
            pci_mode: false,
            tx_notify: 0,
            rx_notify: 0,
        }
    }
}

struct ConsoleCell(UnsafeCell<VirtioConsole>);
// SAFETY: all mutation is serialised by `kernel_bare::serial`'s spinlock
// (see module-level comment).
unsafe impl Sync for ConsoleCell {}

static CONSOLE: ConsoleCell = ConsoleCell(UnsafeCell::new(VirtioConsole::new()));

// TX/RX ring index state. Atomic so cross-core access is data-race-free at
// the language level. The actual TX serialisation is done by the caller
// (kernel_bare::serial holds a spinlock around the whole `puts`/`putc` call).
// Atomic ops here defend against future callers that bypass that lock and
// let Miri verify the soundness of any concurrent test.
static CON_TX_AVAIL_IDX: AtomicU16 = AtomicU16::new(0);
static CON_TX_LAST_USED: AtomicU16 = AtomicU16::new(0);
static CON_RX_AVAIL_IDX: AtomicU16 = AtomicU16::new(0);
static CON_RX_LAST_USED: AtomicU16 = AtomicU16::new(0);

// Ring accessors. Helpers take a raw pointer to the queue memory rather
// than a reference, so the call sites can use `&raw mut con.tx_mem` and
// avoid borrow-checker contortions.
// SAFETY: caller must pass a pointer to a valid `ConQueueMem` and uphold
// the per-byte access discipline.

#[inline]
unsafe fn con_desc_addr(mem: *mut ConQueueMem, i: usize) -> *mut u64 {
    unsafe { (*mem).0.as_mut_ptr().add(i * 16) as *mut u64 }
}
#[inline]
unsafe fn con_desc_len(mem: *mut ConQueueMem, i: usize) -> *mut u32 {
    unsafe { (*mem).0.as_mut_ptr().add(i * 16 + 8) as *mut u32 }
}
#[inline]
unsafe fn con_desc_flags(mem: *mut ConQueueMem, i: usize) -> *mut u16 {
    unsafe { (*mem).0.as_mut_ptr().add(i * 16 + 12) as *mut u16 }
}
#[inline]
unsafe fn con_avail_idx_reg(mem: *mut ConQueueMem) -> *mut u16 {
    unsafe { (*mem).0.as_mut_ptr().add(CON_AVAIL_OFF + 2) as *mut u16 }
}
#[inline]
unsafe fn con_avail_ring(mem: *mut ConQueueMem, i: usize) -> *mut u16 {
    unsafe { (*mem).0.as_mut_ptr().add(CON_AVAIL_OFF + 4 + i * 2) as *mut u16 }
}
#[inline]
unsafe fn con_used_idx_reg(mem: *const ConQueueMem) -> *const u16 {
    unsafe { (*mem).0.as_ptr().add(CON_USED_OFF + 2) as *const u16 }
}
#[inline]
unsafe fn con_used_ring_id(mem: *const ConQueueMem, i: usize) -> *const u32 {
    unsafe { (*mem).0.as_ptr().add(CON_USED_OFF + 4 + i * 8) as *const u32 }
}

// ---- MMIO console init -------------------------------------------------------

/// SAFETY: caller must pass a pointer to a valid `ConQueueMem`.
unsafe fn con_init_mmio_queue(base: u64, qidx: u32, mem: *mut ConQueueMem, is_v2: bool) -> bool {
    unsafe {
        mmio_write32(base + MMIO_QUEUE_SEL, qidx);
        let qmax = mmio_read32(base + MMIO_QUEUE_NUM_MAX);
        if qmax == 0 {
            return false;
        }
        let qs = if (CON_QS as u32) < qmax {
            CON_QS as u32
        } else {
            qmax
        };
        mmio_write32(base + MMIO_QUEUE_NUM, qs);

        if is_v2 {
            let desc_addr = (*mem).0.as_ptr() as u64;
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
            mmio_write32(
                base + MMIO_QUEUE_PFN,
                ((*mem).0.as_ptr() as u64 >> 12) as u32,
            );
        }
    }
    true
}

fn con_init_mmio(base_addr: u64) -> bool {
    unsafe {
        if mmio_read32(base_addr + MMIO_MAGIC_VALUE) != MMIO_MAGIC {
            return false;
        }
        let ver = mmio_read32(base_addr + MMIO_VERSION);
        if ver != 1 && ver != 2 {
            return false;
        }
        if mmio_read32(base_addr + MMIO_DEVICE_ID) != 3 {
            return false;
        }

        let is_v2 = ver == 2;

        // Reset -> ACKNOWLEDGE -> DRIVER
        mmio_write32(base_addr + MMIO_STATUS, 0);
        mmio_write32(base_addr + MMIO_STATUS, STATUS_ACKNOWLEDGE as u32);
        mmio_write32(
            base_addr + MMIO_STATUS,
            (STATUS_ACKNOWLEDGE | STATUS_DRIVER) as u32,
        );

        if is_v2 {
            mmio_write32(base_addr + MMIO_DRIVER_FEATURES_SEL, 0);
            mmio_write32(base_addr + MMIO_GUEST_FEATURES, 0);
            mmio_write32(base_addr + MMIO_DRIVER_FEATURES_SEL, 1);
            mmio_write32(base_addr + MMIO_GUEST_FEATURES, 0);
            mmio_write32(
                base_addr + MMIO_STATUS,
                (STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK) as u32,
            );
            if (mmio_read32(base_addr + MMIO_STATUS) & STATUS_FEATURES_OK as u32) == 0 {
                mmio_write32(base_addr + MMIO_STATUS, STATUS_FAILED as u32);
                return false;
            }
        } else {
            mmio_write32(base_addr + MMIO_GUEST_FEATURES, 0);
            mmio_write32(base_addr + MMIO_GUEST_PAGE_SIZE, 4096);
        }

        // SAFETY: console access is serialised by kernel_bare::serial — no
        // concurrent readers or writers are live during init.
        let con = &mut *CONSOLE.0.get();

        // Zero ring memory
        ptr::write_bytes(con.rx_mem.0.as_mut_ptr(), 0, 8192);
        ptr::write_bytes(con.tx_mem.0.as_mut_ptr(), 0, 8192);

        if !con_init_mmio_queue(base_addr, 0, &raw mut con.rx_mem, is_v2) {
            return false;
        }
        if !con_init_mmio_queue(base_addr, 1, &raw mut con.tx_mem, is_v2) {
            return false;
        }

        // Pre-populate RX descriptors
        for i in 0..CON_QS {
            ptr::write_volatile(
                con_desc_addr(&raw mut con.rx_mem, i),
                con.rx_bufs.as_ptr().add(i) as u64,
            );
            ptr::write_volatile(con_desc_len(&raw mut con.rx_mem, i), 1);
            ptr::write_volatile(con_desc_flags(&raw mut con.rx_mem, i), VIRTQ_DESC_F_WRITE);
            ptr::write_volatile(con_avail_ring(&raw mut con.rx_mem, i), i as u16);
        }
        CON_RX_AVAIL_IDX.store(CON_QS as u16, Ordering::Relaxed);
        dsb_st();
        ptr::write_volatile(con_avail_idx_reg(&raw mut con.rx_mem), CON_QS as u16);
        dsb_sy();
        mmio_write32(base_addr + MMIO_QUEUE_NOTIFY, 0);

        // TX descriptor 0
        ptr::write_volatile(
            con_desc_addr(&raw mut con.tx_mem, 0),
            con.tx_buf.as_ptr() as u64,
        );
        ptr::write_volatile(con_desc_len(&raw mut con.tx_mem, 0), 1);
        ptr::write_volatile(con_desc_flags(&raw mut con.tx_mem, 0), 0);

        let mut final_status = (STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK) as u32;
        if is_v2 {
            final_status |= STATUS_FEATURES_OK as u32;
        }
        mmio_write32(base_addr + MMIO_STATUS, final_status);

        con.base = base_addr;
        con.pci_mode = false;
    }
    true
}

// ---- PCI console init --------------------------------------------------------

fn con_init_pci() -> bool {
    // Find console device (type 3) using Rust PCI infrastructure
    let vpci_idx = match vpci_find(3) {
        Some(i) => i,
        None => return false,
    };

    let dev_snap = vpci_device(vpci_idx);
    let dev = &dev_snap;

    vpci_reset(dev);
    vpci_set_status(dev, STATUS_ACKNOWLEDGE);
    vpci_set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    vpci_write_features(dev, 0, 0);
    vpci_write_features(dev, 1, 1); // VIRTIO_F_VERSION_1
    vpci_set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
    if (vpci_get_status(dev) & STATUS_FEATURES_OK) == 0 {
        vpci_set_status(dev, STATUS_FAILED);
        return false;
    }

    // SAFETY: console access is serialised by kernel_bare::serial — no
    // concurrent readers or writers are live during init.
    let con = unsafe { &mut *CONSOLE.0.get() };

    unsafe {
        ptr::write_bytes(con.rx_mem.0.as_mut_ptr(), 0, 8192);
        ptr::write_bytes(con.tx_mem.0.as_mut_ptr(), 0, 8192);
    }

    // Init RX queue (0)
    vpci_select_queue(dev, 0);
    let qmax = vpci_get_queue_size(dev);
    if qmax == 0 {
        return false;
    }
    let desc_addr = con.rx_mem.0.as_ptr() as u64;
    let avail_addr = desc_addr + CON_AVAIL_OFF as u64;
    let used_addr = desc_addr + CON_USED_OFF as u64;
    vpci_set_queue_addrs(dev, desc_addr, avail_addr, used_addr);
    vpci_enable_queue(dev);

    // Init TX queue (1)
    vpci_select_queue(dev, 1);
    let qmax_tx = vpci_get_queue_size(dev);
    if qmax_tx == 0 {
        return false;
    }
    let desc_addr = con.tx_mem.0.as_ptr() as u64;
    let avail_addr = desc_addr + CON_AVAIL_OFF as u64;
    let used_addr = desc_addr + CON_USED_OFF as u64;
    vpci_set_queue_addrs(dev, desc_addr, avail_addr, used_addr);
    vpci_enable_queue(dev);

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
            ptr::write_volatile(
                con_desc_addr(&raw mut con.rx_mem, i),
                con.rx_bufs.as_ptr().add(i) as u64,
            );
            ptr::write_volatile(con_desc_len(&raw mut con.rx_mem, i), 1);
            ptr::write_volatile(con_desc_flags(&raw mut con.rx_mem, i), VIRTQ_DESC_F_WRITE);
            ptr::write_volatile(con_avail_ring(&raw mut con.rx_mem, i), i as u16);
        }
        CON_RX_AVAIL_IDX.store(CON_QS as u16, Ordering::Relaxed);
        dsb_st();
        ptr::write_volatile(con_avail_idx_reg(&raw mut con.rx_mem), CON_QS as u16);
        dsb_sy();

        // TX descriptor 0
        ptr::write_volatile(
            con_desc_addr(&raw mut con.tx_mem, 0),
            con.tx_buf.as_ptr() as u64,
        );
        ptr::write_volatile(con_desc_len(&raw mut con.tx_mem, 0), 1);
        ptr::write_volatile(con_desc_flags(&raw mut con.tx_mem, 0), 0);
    }

    // DRIVER_OK
    vpci_set_status(
        dev,
        STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
    );

    // Kick RX queue
    unsafe {
        ptr::write_volatile(rx_notify as *mut u16, 0);
    }

    con.base = 1; // sentinel
    con.pci_mode = true;
    con.tx_notify = tx_notify;
    con.rx_notify = rx_notify;
    true
}

// ---- Console I/O ------------------------------------------------------------

/// Submit one TX chunk (≤ `CON_TX_BUF_LEN` bytes) and spin until
/// the device signals completion. Caller is responsible for chunking
/// longer payloads.
///
/// SAFETY: console access is serialised by kernel_bare::serial.
unsafe fn con_tx_one_chunk(con: &mut VirtioConsole, bytes: &[u8]) {
    debug_assert!(bytes.len() <= CON_TX_BUF_LEN);
    unsafe {
        let mut tx_avail = CON_TX_AVAIL_IDX.load(Ordering::Relaxed);
        let mut tx_last = CON_TX_LAST_USED.load(Ordering::Relaxed);

        // Spin until previous TX completes (descriptor 0 is shared).
        while tx_last < tx_avail {
            let u = ptr::read_volatile(con_used_idx_reg(&raw const con.tx_mem));
            if u != tx_last {
                tx_last = u;
                CON_TX_LAST_USED.store(u, Ordering::Relaxed);
            }
            #[cfg(target_arch = "aarch64")]
            asm!("yield", options(nostack, preserves_flags));
            #[cfg(target_arch = "x86_64")]
            asm!("pause", options(nostack, preserves_flags));
        }

        // Copy payload into the static TX buffer and update the
        // descriptor's length. addr / flags were set at init.
        for (i, &b) in bytes.iter().enumerate() {
            con.tx_buf[i] = b;
        }
        ptr::write_volatile(con_desc_len(&raw mut con.tx_mem, 0), bytes.len() as u32);

        dsb_st();
        let slot = (tx_avail % CON_QS as u16) as usize;
        ptr::write_volatile(con_avail_ring(&raw mut con.tx_mem, slot), 0);
        dsb_st();
        ptr::write_volatile(con_avail_idx_reg(&raw mut con.tx_mem), tx_avail + 1);
        tx_avail += 1;
        CON_TX_AVAIL_IDX.store(tx_avail, Ordering::Relaxed);
        dsb_sy();

        if con.pci_mode {
            ptr::write_volatile(con.tx_notify as *mut u16, 1);
        } else {
            mmio_write32(con.base + MMIO_QUEUE_NOTIFY, 1);
        }

        while ptr::read_volatile(con_used_idx_reg(&raw const con.tx_mem)) == tx_last {
            #[cfg(target_arch = "aarch64")]
            asm!("yield", options(nostack, preserves_flags));
            #[cfg(target_arch = "x86_64")]
            asm!("pause", options(nostack, preserves_flags));
        }
        let new_last = ptr::read_volatile(con_used_idx_reg(&raw const con.tx_mem));
        CON_TX_LAST_USED.store(new_last, Ordering::Relaxed);
    }
}

fn con_puts(bytes: &[u8]) {
    // SAFETY: console access is serialised by kernel_bare::serial.
    let con = unsafe { &mut *CONSOLE.0.get() };
    if con.base == 0 {
        return;
    }
    for chunk in bytes.chunks(CON_TX_BUF_LEN) {
        unsafe {
            con_tx_one_chunk(con, chunk);
        }
    }
}

fn con_putc(c: u8) {
    con_puts(&[c]);
}

fn con_try_getc() -> i32 {
    // SAFETY: console access is serialised by kernel_bare::serial.
    let con = unsafe { &mut *CONSOLE.0.get() };
    unsafe {
        if con.base == 0 {
            return -1;
        }

        let rx_last = CON_RX_LAST_USED.load(Ordering::Relaxed);
        let used_idx = ptr::read_volatile(con_used_idx_reg(&raw const con.rx_mem));
        if used_idx == rx_last {
            return -1;
        }

        let slot = (rx_last % CON_QS as u16) as usize;
        let desc_id = ptr::read_volatile(con_used_ring_id(&raw const con.rx_mem, slot)) as usize;
        let c = con.rx_bufs[desc_id] as i32;
        let new_rx_last = rx_last + 1;
        CON_RX_LAST_USED.store(new_rx_last, Ordering::Relaxed);

        // Resubmit descriptor
        ptr::write_volatile(
            con_desc_addr(&raw mut con.rx_mem, desc_id),
            con.rx_bufs.as_ptr().add(desc_id) as u64,
        );
        ptr::write_volatile(con_desc_len(&raw mut con.rx_mem, desc_id), 1);
        ptr::write_volatile(
            con_desc_flags(&raw mut con.rx_mem, desc_id),
            VIRTQ_DESC_F_WRITE,
        );

        let rx_avail = CON_RX_AVAIL_IDX.load(Ordering::Relaxed);
        dsb_st();
        let avail_slot = (rx_avail % CON_QS as u16) as usize;
        ptr::write_volatile(
            con_avail_ring(&raw mut con.rx_mem, avail_slot),
            desc_id as u16,
        );
        dsb_st();
        ptr::write_volatile(con_avail_idx_reg(&raw mut con.rx_mem), rx_avail + 1);
        CON_RX_AVAIL_IDX.store(rx_avail + 1, Ordering::Relaxed);
        dsb_sy();

        // Kick RX queue
        if con.pci_mode {
            ptr::write_volatile(con.rx_notify as *mut u16, 0);
        } else {
            mmio_write32(con.base + MMIO_QUEUE_NOTIFY, 0);
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

/// Write `len` bytes from `ptr` to the console as a single batched
/// TX submission per `CON_TX_BUF_LEN`-byte chunk — one MMIO notify
/// plus one used-ring poll per chunk. Used by
/// `serial::aarch64::puts_raw` for the Virtio backend.
///
/// # Safety
///
/// `ptr` must point at `len` valid bytes for the duration of the
/// call. Caller holds SERIAL_TX_LOCK so no other thread is touching
/// the static console state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn virtio_console_puts(ptr: *const u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    con_puts(bytes);
}

/// Try to read one byte from the console. Returns -1 if nothing available.
#[unsafe(no_mangle)]
pub extern "C" fn virtio_console_try_getc() -> i32 {
    con_try_getc()
}
