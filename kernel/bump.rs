// kernel/bump.rs — Per-core bump allocator for task-scoped allocations.
//
// Simple bump allocator with reset. Each core has its own slab —
// no synchronization needed. Allocations are freed in bulk when
// the task completes (via reset).

/// Size of each core's bump slab: 64KB.
const SLAB_SIZE: usize = 64 * 1024;

/// Per-core bump allocator.
pub struct BumpAllocator {
    slab: [u8; SLAB_SIZE],
    offset: usize,
}

impl BumpAllocator {
    pub const fn new() -> Self {
        BumpAllocator {
            slab: [0; SLAB_SIZE],
            offset: 0,
        }
    }

    /// Allocate `size` bytes with `align` alignment.
    /// Returns a pointer to the allocated region, or null if full.
    pub fn alloc(&mut self, size: usize, align: usize) -> *mut u8 {
        // Align up
        let aligned = (self.offset + align - 1) & !(align - 1);
        if aligned + size > SLAB_SIZE {
            return core::ptr::null_mut();
        }
        let ptr = &mut self.slab[aligned] as *mut u8;
        self.offset = aligned + size;
        ptr
    }

    /// Reset the allocator — frees all allocations at once.
    /// Call after each task completes.
    pub fn reset(&mut self) {
        self.offset = 0;
    }

    /// Bytes remaining in the slab.
    pub fn remaining(&self) -> usize {
        SLAB_SIZE - self.offset
    }

    /// Bytes used.
    pub fn used(&self) -> usize {
        self.offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_basic() {
        let mut bump = BumpAllocator::new();
        let p = bump.alloc(100, 1);
        assert!(!p.is_null());
        assert_eq!(bump.used(), 100);
    }

    #[test]
    fn alloc_aligned() {
        let mut bump = BumpAllocator::new();
        bump.alloc(1, 1); // offset = 1
        let p = bump.alloc(8, 8); // should align to 8
        assert!(!p.is_null());
        assert_eq!(p as usize % 8, 0);
    }

    #[test]
    fn alloc_full() {
        let mut bump = BumpAllocator::new();
        let p = bump.alloc(SLAB_SIZE, 1);
        assert!(!p.is_null());
        assert_eq!(bump.remaining(), 0);
        // Next alloc should fail
        let p2 = bump.alloc(1, 1);
        assert!(p2.is_null());
    }

    #[test]
    fn reset_frees_all() {
        let mut bump = BumpAllocator::new();
        bump.alloc(1000, 1);
        assert_eq!(bump.used(), 1000);
        bump.reset();
        assert_eq!(bump.used(), 0);
        assert_eq!(bump.remaining(), SLAB_SIZE);
        // Can alloc again
        let p = bump.alloc(100, 1);
        assert!(!p.is_null());
    }

    #[test]
    fn multiple_allocs() {
        let mut bump = BumpAllocator::new();
        let p1 = bump.alloc(64, 8);
        let p2 = bump.alloc(128, 16);
        let p3 = bump.alloc(32, 4);
        assert!(!p1.is_null());
        assert!(!p2.is_null());
        assert!(!p3.is_null());
        // All pointers should be different
        assert_ne!(p1, p2);
        assert_ne!(p2, p3);
    }
}
