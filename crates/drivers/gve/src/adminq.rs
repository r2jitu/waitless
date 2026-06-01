// gve admin queue: command building + producer/consumer doorbell
// dance. The device exposes a single in-memory ring of fixed-size
// 64-byte commands; the driver writes commands into the ring, bumps
// a BAR0 doorbell with the producer count, and busy-waits on a
// matching event counter. Each completed slot's first u32 carries a
// device-written status word.
//
// Linux's equivalent is `drivers/net/ethernet/google/gve/gve_adminq.c`.

use core::mem::size_of;
use core::ptr;

use bus::log;
use sync::Spinlock;

use crate::{host_dma_fence, log_hex32, put_be32, read_be32, reg_read32, reg_write32};

// ---- Wire constants --------------------------------------------------------

/// Admin queue ring size in bytes. Single 4 KiB page is required by
/// the device's PFN-addressed `REG_ADMINQ_PFN`.
pub(crate) const ADMINQ_SIZE: usize = 4096;
const ADMINQ_SLOTS: usize = 64;
const CMD_SIZE: usize = 64;

/// Maximum spin iterations waiting for the device to ack a kick.
/// Linux allows many seconds here; we need generous room for the
/// device to service DESCRIBE_DEVICE in a freshly-booted VM.
const ADMINQ_WAIT_SPINS: u32 = 10_000_000;

// Completion-status word values that the device writes into the
// first u32 of each completed slot. Only PASSED means the command
// succeeded; any other value is logged via `check_slot_status`.
const STATUS_PASSED: u32 = 0x1;

// BAR0 register offsets — admin queue lives here.
const REG_ADMINQ_PFN: u64 = 0x10;
const REG_ADMINQ_DOORBELL: u64 = 0x14;
const REG_ADMINQ_EVENT_COUNTER: u64 = 0x18;

// Admin queue opcodes (names match `gve_adminq.h::enum gve_adminq_opcodes`).
pub(crate) const OP_DESCRIBE_DEVICE: u32 = 0x1;
pub(crate) const OP_CONFIGURE_DEVICE_RESOURCES: u32 = 0x2;
pub(crate) const OP_REGISTER_PAGE_LIST: u32 = 0x3;
pub(crate) const OP_CREATE_TX_QUEUE: u32 = 0x5;
pub(crate) const OP_CREATE_RX_QUEUE: u32 = 0x6;
pub(crate) const OP_CONFIGURE_RSS: u32 = 0xA;

// ---- Command builder -------------------------------------------------------

/// One slot in the admin queue. 64 bytes, naturally aligned. The
/// first 4 bytes are the opcode; the remaining 60 bytes are an
/// opcode-specific payload that callers fill with `put_be*`. After
/// the device finishes the command it overwrites bytes 4..8 with a
/// status word (`STATUS_PASSED` on success).
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub(crate) struct AdminqCommand {
    bytes: [u8; CMD_SIZE],
}

// Compile-time invariants the rest of this module assumes.
const _: () = {
    assert!(size_of::<AdminqCommand>() == CMD_SIZE);
    assert!(ADMINQ_SIZE / CMD_SIZE == ADMINQ_SLOTS);
};

impl AdminqCommand {
    /// New command with `opcode` at offset 0 and the rest zeroed.
    pub(crate) fn new(opcode: u32) -> Self {
        let mut cmd = AdminqCommand {
            bytes: [0; CMD_SIZE],
        };
        put_be32(&mut cmd.bytes, 0, opcode);
        cmd
    }

    pub(crate) fn put_be16(&mut self, offset: usize, v: u16) {
        crate::put_be16(&mut self.bytes, offset, v);
    }

    pub(crate) fn put_be32(&mut self, offset: usize, v: u32) {
        crate::put_be32(&mut self.bytes, offset, v);
    }

    pub(crate) fn put_be64(&mut self, offset: usize, v: u64) {
        crate::put_be64(&mut self.bytes, offset, v);
    }

    pub(crate) fn put_u8(&mut self, offset: usize, v: u8) {
        self.bytes[offset] = v;
    }

    /// Write a single byte at `offset`. Used for fields that are
    /// inherently 1-byte (queue_format, RSS hash algorithm, …).
    pub(crate) fn set_byte(&mut self, offset: usize, v: u8) {
        self.bytes[offset] = v;
    }
}

// ---- Driver-side admin queue state -----------------------------------------

struct AdminqState {
    /// Virtual address of the admin-queue ring. The device sees only
    /// the corresponding physical PFN, written to `REG_ADMINQ_PFN`
    /// at init.
    va: u64,
    /// Monotonically-increasing command counter. Writing this value
    /// to the doorbell tells the device "I've produced this many
    /// commands total"; the device increments its event counter to
    /// match as it completes each one.
    prod_cnt: u32,
}

static STATE: Spinlock<Option<AdminqState>> = Spinlock::new(None);

// ---- Init ------------------------------------------------------------------

/// Bind the admin queue to the ring at `adminq_va` and program the
/// device's PFN register. The caller is responsible for allocating
/// the ring as a single page-aligned 4 KiB DMA-coherent region.
///
/// Returns false if the ring isn't page-aligned or if PFN write
/// can't be issued (no BAR0 yet).
pub(crate) fn init(adminq_va: u64, adminq_phys: u64) -> bool {
    if (adminq_phys & 0xFFF) != 0 {
        log(b"[gvnic] adminq phys not page-aligned\n");
        return false;
    }
    {
        let mut st = STATE.lock();
        *st = Some(AdminqState {
            va: adminq_va,
            prod_cnt: 0,
        });
    }
    // Program the device's admin-queue PFN. Must be safe because
    // we've published STATE above; no readers exist before this
    // returns and the BAR0 write is the only side effect.
    unsafe {
        reg_write32(REG_ADMINQ_PFN, (adminq_phys >> 12) as u32);
    }
    true
}

// ---- Submission ------------------------------------------------------------

/// Enqueue `cmd` into the next admin-queue slot without ringing the
/// doorbell. Returns `(slot_idx, new_prod_cnt)`. Caller is expected
/// to either:
///   - submit additional commands and then call `kick_and_wait_to`
///     once to flush the whole batch, followed by `check_slot_status`
///     per command, or
///   - call `kick_and_wait_to` immediately for a one-off (the
///     `execute_cmd` wrapper does this).
///
/// Batching matches Linux's `gve_adminq_issue_cmd` +
/// `gve_adminq_kick_and_wait` pattern — instead of paying per-command
/// device-side processing latency (~3 ms each on GCE) sequentially,
/// we let the device pipeline a queued run and wait for the final
/// completion only.
pub(crate) fn submit_no_wait(cmd: &AdminqCommand) -> Option<(usize, u32)> {
    let mut st = STATE.lock();
    let s = st.as_mut()?;
    let slot_idx = (s.prod_cnt as usize) & (ADMINQ_SLOTS - 1);
    let slot_ptr = (s.va as *mut AdminqCommand).wrapping_add(slot_idx);
    unsafe {
        ptr::write_volatile(slot_ptr, *cmd);
    }
    let new_prod = s.prod_cnt.wrapping_add(1);
    s.prod_cnt = new_prod;
    Some((slot_idx, new_prod))
}

/// Doorbell with the producer count and spin until the device's
/// event counter catches up. Returns false on timeout. Status of
/// each individual command must be checked separately via
/// `check_slot_status`.
pub(crate) fn kick_and_wait_to(expected_event_count: u32) -> bool {
    // Drain the store buffer so the just-written admin command(s)
    // are visible to the device's DMA-read before the doorbell TLP
    // arrives. See `crate::host_dma_fence` for the full mechanism.
    // Without this the device can read a stale command slot
    // (status=0) and either reject the command or execute garbage.
    host_dma_fence();
    unsafe {
        reg_write32(REG_ADMINQ_DOORBELL, expected_event_count);
    }
    for _ in 0..ADMINQ_WAIT_SPINS {
        let ev = unsafe { reg_read32(REG_ADMINQ_EVENT_COUNTER) };
        if ev == expected_event_count {
            return true;
        }
        core::hint::spin_loop();
    }
    log(b"[gvnic] admin queue timeout\n");
    false
}

/// Verify a previously-submitted slot's status word is
/// `STATUS_PASSED`. `label` is logged on failure to identify the
/// failing command.
pub(crate) fn check_slot_status(slot_idx: usize, label: &[u8]) -> bool {
    let status = unsafe { read_slot_status(slot_idx) };
    if status != STATUS_PASSED {
        log(b"[gvnic] ");
        log(label);
        log(b": status=");
        log_hex32(status);
        log(b"\n");
        return false;
    }
    true
}

/// Submit `cmd`, wait for the device, and check that the per-command
/// status is PASSED. Logs and returns false on any failure (timeout
/// or non-zero status). Used by every admin-queue command after
/// DESCRIBE_DEVICE.
pub(crate) fn execute_cmd(opcode_label: &[u8], cmd: &AdminqCommand) -> bool {
    let (_slot, prod) = match submit_no_wait(cmd) {
        Some(x) => x,
        None => return false,
    };
    if !kick_and_wait_to(prod) {
        log(b"[gvnic] ");
        log(opcode_label);
        log(b": timeout\n");
        return false;
    }
    check_slot_status(current_slot_before_kick(), opcode_label)
}

// ---- Internal helpers ------------------------------------------------------

/// After `submit_no_wait` returns, the slot we just used is
/// `(prod_cnt - 1) & mask`. Used to read back the device's status
/// write for a single-command submission.
fn current_slot_before_kick() -> usize {
    let st = STATE.lock();
    let s = st.as_ref().expect("adminq state");
    ((s.prod_cnt - 1) as usize) & (ADMINQ_SLOTS - 1)
}

/// Read the status word the device wrote into slot `slot_idx`. The
/// status occupies bytes 4..8 of the slot (big-endian).
///
/// # Safety
/// `slot_idx < ADMINQ_SLOTS` must hold; caller is responsible for
/// having called `kick_and_wait_to` so the device has actually
/// written the status (otherwise reads zero).
unsafe fn read_slot_status(slot_idx: usize) -> u32 {
    debug_assert!(slot_idx < ADMINQ_SLOTS);
    let st = STATE.lock();
    let s = st.as_ref().expect("adminq state");
    let slot_ptr = (s.va as *const AdminqCommand).wrapping_add(slot_idx);
    let slot = unsafe { &*slot_ptr };
    read_be32(&slot.bytes, 4)
}
