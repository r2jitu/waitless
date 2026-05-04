// kernel/spsc.rs — Lock-free SPSC ring buffer.
//
// Single-producer, single-consumer fixed-size ring buffer.
// Used for: pinned task queues, per-core inbox (Tier 2 RX delivery),
// and per-core TX staging buffers.
//
// `push` and `pop` both take `&self`: the producer and the consumer
// hold *shared* references to the same `Ring` and synchronise via the
// atomic `head` / `tail` indices, with the buffer slots in `UnsafeCell`
// for interior mutability. This is what makes a true cross-core SPSC
// queue sound in Rust — taking `&mut self` on either side would
// require aliased mutable references when the producer and consumer
// run on different cores, which is undefined behaviour.
//
// Soundness rule (NOT enforced by the type system, must be upheld by
// callers): at most one thread/core ever calls `push`, and at most
// one ever calls `pop`. The producer and consumer may be different
// cores. `len`/`is_empty` may be called from anywhere.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Fixed capacity. Must be a power of 2.
const CAPACITY: usize = 256;
const MASK: usize = CAPACITY - 1;

/// SPSC ring buffer for fixed-size items.
pub struct Ring<T: Copy + Zero> {
    buffer: [UnsafeCell<T>; CAPACITY],
    head: AtomicUsize, // consumer reads from head
    tail: AtomicUsize, // producer writes to tail
}

// SAFETY: cross-core sharing is sound provided the SPSC discipline above
// is followed: one producer, one consumer, synchronisation via the atomic
// head/tail with Acquire/Release ordering. The `T: Send` bound ensures the
// item can be transferred between cores.
unsafe impl<T: Copy + Zero + Send> Sync for Ring<T> {}

impl<T: Copy + Zero> Ring<T> {
    pub const fn new() -> Self {
        Ring {
            buffer: [const { UnsafeCell::new(T::ZERO) }; CAPACITY],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    /// Push an item (producer only). Returns false if full.
    pub fn push(&self, item: T) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if tail - head >= CAPACITY {
            return false;
        }
        // SAFETY: only the producer writes to buffer slots, and the slot
        // at index (tail & MASK) is not visible to the consumer until we
        // perform the release-store on `tail` below. The acquire-load on
        // `head` above ensures the consumer is finished with this slot
        // (the previous wrap of it) before we overwrite.
        unsafe { *self.buffer[tail & MASK].get() = item; }
        self.tail.store(tail + 1, Ordering::Release);
        true
    }

    /// Pop an item (consumer only). Returns None if empty.
    pub fn pop(&self) -> Option<T> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head >= tail {
            return None;
        }
        // SAFETY: head < tail (acquire-loaded above) means the producer
        // has finished writing this slot and released `tail`. Only the
        // consumer reads slot contents before its own release-store on
        // `head`, so the read does not race with any other reader.
        let item = unsafe { *self.buffer[head & MASK].get() };
        self.head.store(head + 1, Ordering::Release);
        Some(item)
    }

    /// Number of items in the ring.
    pub fn len(&self) -> usize {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Relaxed);
        if tail >= head { tail - head } else { 0 }
    }

    /// True if the ring is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Const-callable "zero value" trait for ring-buffer slot init. Lives
/// here rather than reusing `core::default::Default` because we need
/// a `const`-callable value (slot init runs in `const fn new()` /
/// `const { … }` array repeat); `Default::default()` isn't const.
pub trait Zero: Sized {
    const ZERO: Self;
}

impl Zero for usize {
    const ZERO: Self = 0;
}

impl Zero for u64 {
    const ZERO: Self = 0;
}

impl Zero for u32 {
    const ZERO: Self = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_pop() {
        let r = Ring::<usize>::new();
        assert!(r.is_empty());
        assert!(r.push(42));
        assert_eq!(r.len(), 1);
        assert_eq!(r.pop(), Some(42));
        assert!(r.is_empty());
    }

    #[test]
    fn fifo_order() {
        let r = Ring::<usize>::new();
        r.push(1);
        r.push(2);
        r.push(3);
        assert_eq!(r.pop(), Some(1));
        assert_eq!(r.pop(), Some(2));
        assert_eq!(r.pop(), Some(3));
        assert!(r.pop().is_none());
    }

    #[test]
    fn pop_empty() {
        let r = Ring::<usize>::new();
        assert!(r.pop().is_none());
    }

    #[test]
    fn capacity_full() {
        let r = Ring::<usize>::new();
        for i in 0..CAPACITY {
            assert!(r.push(i));
        }
        assert!(!r.push(999));
        assert_eq!(r.len(), CAPACITY);
    }

    #[test]
    fn wrap_around() {
        let r = Ring::<usize>::new();
        for round in 0..3 {
            for i in 0..100 {
                assert!(r.push(round * 100 + i));
            }
            for i in 0..100 {
                assert_eq!(r.pop(), Some(round * 100 + i));
            }
            assert!(r.is_empty());
        }
    }

    /// Cross-thread SPSC: producer thread and consumer thread share the
    /// same Ring via shared references. This is the case the unikernel
    /// actually exercises (one core pushes, another pops). It would be
    /// undefined behaviour if push/pop took `&mut self`.
    #[test]
    fn spsc_two_threads() {
        use std::sync::Arc;
        use std::thread;

        const N: usize = 10_000;
        let r = Arc::new(Ring::<usize>::new());
        let producer = {
            let r = Arc::clone(&r);
            thread::spawn(move || {
                let mut i = 0;
                while i < N {
                    if r.push(i) {
                        i += 1;
                    } else {
                        std::thread::yield_now();
                    }
                }
            })
        };
        let consumer = {
            let r = Arc::clone(&r);
            thread::spawn(move || {
                let mut next = 0;
                while next < N {
                    match r.pop() {
                        Some(v) => {
                            assert_eq!(v, next);
                            next += 1;
                        }
                        None => std::thread::yield_now(),
                    }
                }
            })
        };
        producer.join().unwrap();
        consumer.join().unwrap();
        assert!(r.is_empty());
    }
}
