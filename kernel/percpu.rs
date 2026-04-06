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
const TX_POOL_SIZE: usize = 32;

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

/// Per-core state. Each core has exactly one of these.
pub struct PerCore {
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

    /// Core ID.
    pub id: u32,
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
            inbox: spsc::Ring::new(),
            pinned: spsc::Ring::new(),
            stealable: Deque::new(),
            timers: TimerWheel::new(),
            pending_timers: PendingTimers::new(),
            tx_staging: TxStaging::new(),
            id,
        }
    }
}

/// Global array of per-core state. Initialized by core 0 during boot.
static mut CORES: [PerCore; MAX_CORES] = [const { PerCore::new(0) }; MAX_CORES];
static mut NUM_CORES: u32 = 1;

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
