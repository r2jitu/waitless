// tools/hvf-runner/src/spsc.rs
//
// Lock-free single-producer single-consumer (SPSC) ring buffer.
// One thread pushes, one thread pops — no locks, no CAS, just
// Release/Acquire atomics on two cache-line-aligned indices.
//
// Used to decouple the IO thread (socket read/write) from the
// vCPU thread (guest virtio ring injection/extraction).

use std::sync::atomic::{AtomicUsize, Ordering};

/// A pre-allocated frame slot in the ring.
const FRAME_CAP: usize = 2048;

struct Slot {
    data: [u8; FRAME_CAP],
    len: usize,
}

impl Slot {
    const EMPTY: Self = Slot { data: [0; FRAME_CAP], len: 0 };
}

/// Lock-free SPSC ring buffer for Ethernet frames.
///
/// The ring has `CAP` slots. The producer writes at `head` (mod CAP)
/// and the consumer reads at `tail` (mod CAP). The ring is full when
/// `head - tail == CAP` and empty when `head == tail`.
///
/// Cache lines: head and tail are on separate cache lines to avoid
/// false sharing between the producer and consumer cores.
pub struct SpscRing<const CAP: usize> {
    slots: Box<[Slot; CAP]>,
    head: CacheAligned,
    tail: CacheAligned,
}

#[repr(align(128))]
struct CacheAligned {
    val: AtomicUsize,
}

impl CacheAligned {
    const fn new() -> Self {
        CacheAligned { val: AtomicUsize::new(0) }
    }
}

impl<const CAP: usize> SpscRing<CAP> {
    /// Create a new ring with CAP pre-allocated frame slots.
    pub fn new() -> Self {
        SpscRing {
            slots: Box::new([const { Slot::EMPTY }; CAP]),
            head: CacheAligned::new(),
            tail: CacheAligned::new(),
        }
    }

    /// Try to push a frame. Returns false if the ring is full.
    /// Called by the producer thread only.
    pub fn push(&self, data: &[u8]) -> bool {
        let head = self.head.val.load(Ordering::Relaxed);
        let tail = self.tail.val.load(Ordering::Acquire);
        if head.wrapping_sub(tail) >= CAP {
            return false; // full
        }
        let idx = head % CAP;
        let len = data.len().min(FRAME_CAP);
        // SAFETY: only the producer writes to slots[idx] when head is at this position.
        // The consumer won't read this slot until head is advanced (Release below).
        unsafe {
            let slot = &mut *(self.slots.as_ptr().add(idx) as *mut Slot);
            slot.data[..len].copy_from_slice(&data[..len]);
            slot.len = len;
        }
        self.head.val.store(head.wrapping_add(1), Ordering::Release);
        true
    }

    /// Try to pop a frame into the provided closure. Returns false if empty.
    /// Called by the consumer thread only.
    pub fn pop<F: FnMut(&[u8])>(&self, mut f: F) -> bool {
        let tail = self.tail.val.load(Ordering::Relaxed);
        let head = self.head.val.load(Ordering::Acquire);
        if tail == head {
            return false; // empty
        }
        let idx = tail % CAP;
        // SAFETY: only the consumer reads slots[idx] when tail is at this position.
        // The producer won't overwrite until tail is advanced (Release below).
        let slot = unsafe { &*self.slots.as_ptr().add(idx) };
        f(&slot.data[..slot.len]);
        self.tail.val.store(tail.wrapping_add(1), Ordering::Release);
        true
    }

    /// Check if the ring has data without consuming.
    pub fn is_empty(&self) -> bool {
        let tail = self.tail.val.load(Ordering::Relaxed);
        let head = self.head.val.load(Ordering::Acquire);
        tail == head
    }

    /// Number of frames in the ring.
    pub fn len(&self) -> usize {
        let tail = self.tail.val.load(Ordering::Relaxed);
        let head = self.head.val.load(Ordering::Acquire);
        head.wrapping_sub(tail)
    }
}

// SAFETY: The ring is designed for cross-thread use (producer on one thread,
// consumer on another). The atomic indices provide the synchronization.
unsafe impl<const CAP: usize> Send for SpscRing<CAP> {}
unsafe impl<const CAP: usize> Sync for SpscRing<CAP> {}
