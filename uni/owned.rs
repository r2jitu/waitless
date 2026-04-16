// uni/owned.rs — Heap-owned smart pointers built on uni::heap.
//
// Two types:
//   * `Box<T>`: owning heap allocation of a single `T`. Like `alloc::Box`
//     and `kernel::kbox::KBox`, but works on both unikernel and native
//     backends without depending on either crate. Drops via uni::heap.
//   * `Buffer`: heap-owned, zero-initialised `[u8]`. Allocates the bytes
//     directly from the heap (no stack temporary), so it's safe to use
//     for buffers larger than the kernel boot stack.
//
// `Box::leak(b) -> &'static mut T` is the only escape from owned access;
// it's intended for boot-time singletons whose lifetime is the entire
// program (e.g. the HTTP `Server`).

use core::marker::PhantomData;
use core::mem;
use core::ops::{Deref, DerefMut};
use core::ptr::{self, NonNull};
use core::slice;

use crate::heap;

// ============================================================================
// Box<T> — owning heap allocation of a single T
// ============================================================================

#[repr(transparent)]
pub struct Box<T: ?Sized> {
    ptr: NonNull<T>,
    _own: PhantomData<T>,
}

// SAFETY: Box is the unique owner of its allocation. Send/Sync follow
// from T's bounds, exactly as alloc::Box does.
unsafe impl<T: ?Sized + Send> Send for Box<T> {}
unsafe impl<T: ?Sized + Sync> Sync for Box<T> {}

impl<T> Box<T> {
    /// Allocate a `T` on the heap and move `value` into it. Aborts on OOM.
    #[inline]
    pub fn new(value: T) -> Self {
        let raw = heap::alloc(mem::size_of::<T>()) as *mut T;
        let ptr = NonNull::new(raw).expect("uni::Box: out of memory");
        // SAFETY: we just allocated; the pointer is non-null, aligned
        // (heap returns 16-byte alignment), exclusively owned, and the
        // write fills uninitialised memory.
        unsafe { ptr.as_ptr().write(value); }
        Box { ptr, _own: PhantomData }
    }
}

impl<T: ?Sized> Box<T> {
    /// Consume the box and return a `&'static mut T`. The allocation is
    /// never freed; intended only for boot-time singletons whose lifetime
    /// is the entire program. Equivalent to `alloc::Box::leak`.
    ///
    /// Discarding the returned reference silently leaks the allocation
    /// with no way to recover it, so the `#[must_use]` is strict.
    #[inline]
    #[must_use = "the leaked reference is the only access to this allocation"]
    pub fn leak(self) -> &'static mut T {
        let raw = self.ptr.as_ptr();
        mem::forget(self);
        // SAFETY: into_raw transfers ownership of a live allocation; we
        // are now the unique referent. Lifetime extension to 'static is
        // sound because nothing in the program ever frees this address.
        unsafe { &mut *raw }
    }
}

impl<T: ?Sized> Deref for Box<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: Box owns a valid `T` for its entire lifetime.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T: ?Sized> DerefMut for Box<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: Box owns a valid `T` and we hold &mut self, so no
        // other reference exists.
        unsafe { self.ptr.as_mut() }
    }
}

impl<T: ?Sized> Drop for Box<T> {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: Box is the unique owner of the allocation; nobody
        // else can be reading it. Drop the inner value first, then
        // free the backing memory.
        unsafe {
            ptr::drop_in_place(self.ptr.as_ptr());
            heap::dealloc(self.ptr.as_ptr() as *mut u8);
        }
    }
}

// ============================================================================
// Buffer — heap-owned, zero-initialised byte slice
// ============================================================================
//
// Used for HTTP per-connection receive buffers and similar fixed-size
// scratch space that's too big for inline storage. Allocates and zeroes
// the bytes directly on the heap — no stack temporary at any size.

pub struct Buffer {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: Buffer is the unique owner of its bytes.
unsafe impl Send for Buffer {}
unsafe impl Sync for Buffer {}

impl Buffer {
    /// Allocate `len` zero-initialised bytes on the heap. Aborts on OOM.
    #[inline]
    pub fn new(len: usize) -> Self {
        assert!(len > 0, "uni::Buffer: zero-length not supported");
        let raw = heap::alloc(len);
        let ptr = NonNull::new(raw).expect("uni::Buffer: out of memory");
        // SAFETY: we just allocated `len` bytes; this fills them before
        // any other code can observe the allocation.
        unsafe { ptr::write_bytes(ptr.as_ptr(), 0, len); }
        Buffer { ptr, len }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }
}

impl Deref for Buffer {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        // SAFETY: Buffer owns `len` valid bytes for its entire lifetime.
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl DerefMut for Buffer {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: Buffer owns `len` valid bytes; &mut self proves
        // exclusive access.
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for Buffer {
    #[inline]
    fn drop(&mut self) {
        // Buffer is the unique owner. Bytes don't need dropping.
        heap::dealloc(self.ptr.as_ptr());
    }
}

