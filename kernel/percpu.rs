// kernel/percpu.rs — Per-core state for the multi-core event loop.
//
// Each core owns a PerCore struct containing its work queues, timer wheel,
// TX staging, and inbox. Core 0 allocates all PerCore structs during boot.

use crate::deque::{Deque, Task};
use crate::spsc;
use crate::timer::{TimerWheel, PendingTimers};

/// Maximum number of cores.
pub const MAX_CORES: usize = 8;

/// Maximum packet size for TX staging.
const TX_BUF_SIZE: usize = 1514;

/// Number of TX staging slots per core.
const TX_POOL_SIZE: usize = 8;

/// A staged TX packet: length + data.
#[derive(Clone, Copy)]
pub struct TxPacket {
    pub len: usize,
    pub data: [u8; TX_BUF_SIZE],
}

impl spsc::Default for TxPacket {
    const DEFAULT: Self = TxPacket { len: 0, data: [0; TX_BUF_SIZE] };
}

impl spsc::Default for Task {
    const DEFAULT: Self = Task { func: noop, arg: 0 };
}

fn noop(_: usize) {}

/// Maximum packet size for RX inbox.
const RX_BUF_SIZE: usize = 1514;

/// Number of RX inbox slots per core.
const RX_POOL_SIZE: usize = 16;

/// A received packet in the inbox: length + data.
#[derive(Clone, Copy)]
pub struct RxPacket {
    pub len: usize,
    pub data: [u8; RX_BUF_SIZE],
}

impl spsc::Default for RxPacket {
    const DEFAULT: Self = RxPacket { len: 0, data: [0; RX_BUF_SIZE] };
}

/// RX inbox: core 0 pushes received frames here, owning core pops and processes.
pub struct RxInbox {
    pool: [RxPacket; RX_POOL_SIZE],
    /// Indices of filled packets, ready for the owning core to process.
    ready: spsc::Ring<u32>,
    next_slot: usize,
}

impl RxInbox {
    pub const fn new() -> Self {
        RxInbox {
            pool: [const { RxPacket { len: 0, data: [0; RX_BUF_SIZE] } }; RX_POOL_SIZE],
            ready: spsc::Ring::new(),
            next_slot: 0,
        }
    }

    /// Push a frame into the inbox (called by core 0 during distribution).
    pub fn push(&mut self, data: &[u8]) -> bool {
        if data.len() > RX_BUF_SIZE {
            return false;
        }
        let slot = self.next_slot;
        self.pool[slot].data[..data.len()].copy_from_slice(data);
        self.pool[slot].len = data.len();
        if !self.ready.push(slot as u32) {
            return false;
        }
        self.next_slot = (self.next_slot + 1) % RX_POOL_SIZE;
        true
    }

    /// Pop a ready frame (called by owning core).
    pub fn pop(&mut self) -> Option<&[u8]> {
        let idx = self.ready.pop()?;
        let pkt = &self.pool[idx as usize];
        Some(&pkt.data[..pkt.len])
    }
}

/// Per-core state. Each core has exactly one of these.
/// The TLS register (GS_BASE on x86_64, TPIDR_EL1 on aarch64) points
/// to this struct. Fields at known offsets can be read directly via
/// the TLS register without indirection.
///
/// IMPORTANT: `id` must be the first field (offset 0) — cpu_id() reads
/// it directly via `gs:[0]` / TPIDR_EL1 without going through Rust.
#[repr(C)]
pub struct PerCore {
    /// Core ID — MUST be at offset 0 (read by cpu_id() via TLS register).
    pub id: u32,

    _pad: u32, // align next field to 8 bytes

    /// RX inbox for Tier 2 delivery (core 0 writes, this core reads).
    pub rx_inbox: RxInbox,

    /// Inbox for Tier 2 RX delivery (SPSC: core 0 writes, this core reads).
    pub inbox: spsc::Ring<Task>,

    /// Pinned tasks — connection-bound work, only this core reads/writes.
    pub pinned: spsc::Ring<Task>,

    /// Stealable tasks — pure compute, thieves can steal from here.
    pub stealable: Deque,

    /// Timer wheel — only this core fires timers.
    pub timers: TimerWheel,

    /// Pending timers — any core can push, this core drains into wheel.
    pub pending_timers: PendingTimers,

    /// TX staging buffer — this core writes packets here, core 0 flushes (Tier 2).
    pub tx_staging: TxStaging,
}

/// TX staging: fixed pool of packet buffers + SPSC index ring.
pub struct TxStaging {
    pool: [TxPacket; TX_POOL_SIZE],
    /// Indices of filled packets, ready for core 0 to flush.
    ready: spsc::Ring<u32>,
    next_slot: usize,
}

impl TxStaging {
    pub const fn new() -> Self {
        TxStaging {
            pool: [const { TxPacket { len: 0, data: [0; TX_BUF_SIZE] } }; TX_POOL_SIZE],
            ready: spsc::Ring::new(),
            next_slot: 0,
        }
    }

    /// Stage a packet for transmission (called by owning core).
    pub fn push(&mut self, data: &[u8]) -> bool {
        if data.len() > TX_BUF_SIZE {
            return false;
        }
        let slot = self.next_slot;
        if slot >= TX_POOL_SIZE {
            return false; // pool exhausted
        }
        self.pool[slot].data[..data.len()].copy_from_slice(data);
        self.pool[slot].len = data.len();
        if !self.ready.push(slot as u32) {
            return false;
        }
        self.next_slot += 1;
        if self.next_slot >= TX_POOL_SIZE {
            self.next_slot = 0; // wrap
        }
        true
    }

    /// Pop a ready packet (called by core 0 during flush).
    pub fn pop(&mut self) -> Option<&[u8]> {
        let idx = self.ready.pop()?;
        let pkt = &self.pool[idx as usize];
        Some(&pkt.data[..pkt.len])
    }
}

impl PerCore {
    pub const fn new(id: u32) -> Self {
        PerCore {
            id,
            _pad: 0,
            rx_inbox: RxInbox::new(),
            inbox: spsc::Ring::new(),
            pinned: spsc::Ring::new(),
            stealable: Deque::new(),
            timers: TimerWheel::new(),
            pending_timers: PendingTimers::new(),
            tx_staging: TxStaging::new(),
        }
    }
}

/// Global array of per-core state. Initialized by core 0 during boot.
static mut CORES: [PerCore; MAX_CORES] = [const { PerCore::new(0) }; MAX_CORES];
static mut NUM_CORES: u32 = 1;

/// AP poll function: registered by the network layer, called by APs in
/// their event loop. Returns true if work was done.
///
/// Stored as `AtomicPtr<()>` rather than `static mut` so the cross-core
/// publish/subscribe is a real release/acquire pair, not a volatile read
/// (which is not a synchronisation primitive). The `Option<fn>` is encoded
/// as a nullable raw pointer: null = `None`, non-null = `Some(fn)`.
static AP_POLL_FN: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Initialize per-core state for `count` cores.
pub unsafe fn init(count: u32) {
    unsafe {
        let n = count.min(MAX_CORES as u32);
        NUM_CORES = n;
        for i in 0..n {
            CORES[i as usize].id = i;
        }
    }
}

/// Get a mutable reference to a core's state.
pub unsafe fn get(id: u32) -> &'static mut PerCore {
    unsafe { &mut CORES[id as usize] }
}

/// Get the total number of cores.
pub fn num_cores() -> u32 {
    unsafe { NUM_CORES }
}

/// Register the AP poll function (called by net layer during init).
/// Release-stores the pointer so APs that observe it via acquire-load
/// also see all writes that happened-before this store.
pub fn set_ap_poll_fn(f: fn(u32) -> bool) {
    AP_POLL_FN.store(f as *mut (), core::sync::atomic::Ordering::Release);
}

/// Get the AP poll function (called by APs in their event loop).
/// Acquire-loads to pair with `set_ap_poll_fn`'s release-store.
pub fn ap_poll_fn() -> Option<fn(u32) -> bool> {
    let p = AP_POLL_FN.load(core::sync::atomic::Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: only `set_ap_poll_fn` writes here, and it always writes a
        // valid `fn(u32) -> bool` pointer.
        Some(unsafe { core::mem::transmute::<*mut (), fn(u32) -> bool>(p) })
    }
}
