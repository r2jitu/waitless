// kernel/deque.rs — Chase-Lev work-stealing deque.
//
// Lock-free deque for cooperative work stealing:
// - Owner pushes/pops from the "bottom" (LIFO, cache-friendly)
// - Thieves steal from the "top" (FIFO, single CAS)
//
// Fixed-size (no allocation), suitable for bare-metal.
// Based on "Dynamic Circular Work-Stealing Deque" (Chase & Lev, 2005).

use core::sync::atomic::{AtomicUsize, Ordering};

/// Fixed capacity of the deque. Must be a power of 2.
const CAPACITY: usize = 256;
const MASK: usize = CAPACITY - 1;

/// A task stored in the deque. Opaque function pointer + context.
#[derive(Clone, Copy)]
pub struct Task {
    pub func: fn(usize),
    pub arg: usize,
}

/// Chase-Lev work-stealing deque.
///
/// Owner (single thread): push() and pop() from the bottom.
/// Thieves (any thread): steal() from the top.
pub struct Deque {
    buffer: [Option<Task>; CAPACITY],
    bottom: AtomicUsize,
    top: AtomicUsize,
}

impl Deque {
    pub const fn new() -> Self {
        Deque {
            buffer: [None; CAPACITY],
            bottom: AtomicUsize::new(0),
            top: AtomicUsize::new(0),
        }
    }

    /// Push a task onto the bottom (owner only). Returns false if full.
    pub fn push(&mut self, task: Task) -> bool {
        let b = self.bottom.load(Ordering::Relaxed);
        let t = self.top.load(Ordering::Acquire);
        if b - t >= CAPACITY {
            return false; // full
        }
        self.buffer[b & MASK] = Some(task);
        // Release: make the write visible before advancing bottom
        self.bottom.store(b + 1, Ordering::Release);
        true
    }

    /// Pop a task from the bottom (owner only). Returns None if empty.
    pub fn pop(&mut self) -> Option<Task> {
        let b = self.bottom.load(Ordering::Relaxed);
        if b == 0 {
            return None;
        }
        let b = b - 1;
        self.bottom.store(b, Ordering::SeqCst);

        let t = self.top.load(Ordering::SeqCst);
        if t <= b {
            // Non-empty: safe to take
            let task = self.buffer[b & MASK].take();
            return task;
        }

        // Deque has one element (or is empty due to concurrent steal)
        if t == b {
            // Race with steal — try CAS on top
            let result = self.top.compare_exchange(
                t,
                t + 1,
                Ordering::SeqCst,
                Ordering::Relaxed,
            );
            self.bottom.store(t + 1, Ordering::Relaxed);
            if result.is_ok() {
                return self.buffer[b & MASK].take();
            }
        }

        // Empty or lost race
        self.bottom.store(t, Ordering::Relaxed);
        None
    }

    /// Steal a task from the top (any thread). Returns None if empty.
    pub fn steal(&self) -> Option<Task> {
        let t = self.top.load(Ordering::Acquire);
        let b = self.bottom.load(Ordering::Acquire);
        if t >= b {
            return None; // empty
        }
        // Read the task before CAS
        let task = unsafe {
            let ptr = &self.buffer[t & MASK] as *const Option<Task>;
            core::ptr::read_volatile(ptr)
        };
        // Try to advance top (claim this slot)
        let result = self.top.compare_exchange(
            t,
            t + 1,
            Ordering::SeqCst,
            Ordering::Relaxed,
        );
        if result.is_ok() {
            task
        } else {
            None // another thief got it
        }
    }

    /// Number of tasks currently in the deque.
    pub fn len(&self) -> usize {
        let b = self.bottom.load(Ordering::Relaxed);
        let t = self.top.load(Ordering::Relaxed);
        if b >= t { b - t } else { 0 }
    }

    /// True if the deque is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noop(_: usize) {}

    fn make_task(arg: usize) -> Task {
        Task { func: noop, arg }
    }

    #[test]
    fn push_pop_single() {
        let mut d = Deque::new();
        assert!(d.is_empty());
        assert!(d.push(make_task(42)));
        assert_eq!(d.len(), 1);
        let t = d.pop().unwrap();
        assert_eq!(t.arg, 42);
        assert!(d.is_empty());
    }

    #[test]
    fn push_pop_lifo() {
        let mut d = Deque::new();
        d.push(make_task(1));
        d.push(make_task(2));
        d.push(make_task(3));
        // Pop is LIFO
        assert_eq!(d.pop().unwrap().arg, 3);
        assert_eq!(d.pop().unwrap().arg, 2);
        assert_eq!(d.pop().unwrap().arg, 1);
        assert!(d.pop().is_none());
    }

    #[test]
    fn steal_fifo() {
        let mut d = Deque::new();
        d.push(make_task(1));
        d.push(make_task(2));
        d.push(make_task(3));
        // Steal is FIFO
        assert_eq!(d.steal().unwrap().arg, 1);
        assert_eq!(d.steal().unwrap().arg, 2);
        assert_eq!(d.steal().unwrap().arg, 3);
        assert!(d.steal().is_none());
    }

    #[test]
    fn mixed_pop_and_steal() {
        let mut d = Deque::new();
        d.push(make_task(1));
        d.push(make_task(2));
        d.push(make_task(3));
        d.push(make_task(4));
        // Steal takes from top (FIFO), pop from bottom (LIFO)
        assert_eq!(d.steal().unwrap().arg, 1); // top
        assert_eq!(d.pop().unwrap().arg, 4);   // bottom
        assert_eq!(d.steal().unwrap().arg, 2); // next from top
        assert_eq!(d.pop().unwrap().arg, 3);   // next from bottom
        assert!(d.is_empty());
    }

    #[test]
    fn pop_empty() {
        let mut d = Deque::new();
        assert!(d.pop().is_none());
    }

    #[test]
    fn steal_empty() {
        let d = Deque::new();
        assert!(d.steal().is_none());
    }

    #[test]
    fn capacity_full() {
        let mut d = Deque::new();
        for i in 0..CAPACITY {
            assert!(d.push(make_task(i)));
        }
        assert!(!d.push(make_task(999))); // full
        assert_eq!(d.len(), CAPACITY);
    }

    #[test]
    fn wrap_around() {
        let mut d = Deque::new();
        // Fill and drain a few times to exercise wrap-around
        for round in 0..3 {
            for i in 0..100 {
                assert!(d.push(make_task(round * 100 + i)));
            }
            for i in (0..100).rev() {
                assert_eq!(d.pop().unwrap().arg, round * 100 + i);
            }
            assert!(d.is_empty());
        }
    }
}
