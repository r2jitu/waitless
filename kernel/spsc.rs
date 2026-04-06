// kernel/spsc.rs — Lock-free SPSC ring buffer.
//
// Single-producer, single-consumer fixed-size ring buffer.
// Used for: pinned task queues, per-core inbox (Tier 2 RX delivery),
// and per-core TX staging buffers.
//
// No atomics on the fast path when used single-threaded.
// Uses Acquire/Release on head/tail for cross-core SPSC (inbox/TX staging).

use core::sync::atomic::{AtomicUsize, Ordering};

/// Fixed capacity. Must be a power of 2.
const CAPACITY: usize = 256;
const MASK: usize = CAPACITY - 1;

/// SPSC ring buffer for fixed-size items.
pub struct Ring<T: Copy + Default> {
    buffer: [T; CAPACITY],
    head: AtomicUsize, // consumer reads from head
    tail: AtomicUsize, // producer writes to tail
}

impl<T: Copy + Default> Ring<T> {
    pub const fn new() -> Self {
        Ring {
            buffer: [T::DEFAULT; CAPACITY],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    /// Push an item (producer only). Returns false if full.
    pub fn push(&mut self, item: T) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if tail - head >= CAPACITY {
            return false;
        }
        self.buffer[tail & MASK] = item;
        self.tail.store(tail + 1, Ordering::Release);
        true
    }

    /// Pop an item (consumer only). Returns None if empty.
    pub fn pop(&mut self) -> Option<T> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head >= tail {
            return None;
        }
        let item = self.buffer[head & MASK];
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

/// Trait for types that can be stored in the ring (need a default/zero value).
pub trait Default: Sized {
    const DEFAULT: Self;
}

impl Default for usize {
    const DEFAULT: Self = 0;
}

impl Default for u64 {
    const DEFAULT: Self = 0;
}

impl Default for u32 {
    const DEFAULT: Self = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_pop() {
        let mut r = Ring::<usize>::new();
        assert!(r.is_empty());
        assert!(r.push(42));
        assert_eq!(r.len(), 1);
        assert_eq!(r.pop(), Some(42));
        assert!(r.is_empty());
    }

    #[test]
    fn fifo_order() {
        let mut r = Ring::<usize>::new();
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
        let mut r = Ring::<usize>::new();
        assert!(r.pop().is_none());
    }

    #[test]
    fn capacity_full() {
        let mut r = Ring::<usize>::new();
        for i in 0..CAPACITY {
            assert!(r.push(i));
        }
        assert!(!r.push(999));
        assert_eq!(r.len(), CAPACITY);
    }

    #[test]
    fn wrap_around() {
        let mut r = Ring::<usize>::new();
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
}
