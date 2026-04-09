// kernel/kbox.rs — Typed owning pointer over the kernel heap allocator.
//
// `KBox<T>` is to `kernel::mm::kmalloc` what `alloc::Box<T>` is to the
// global allocator: a unique owner of a heap allocation that frees on
// drop. It eliminates the manual `kmalloc` / `kfree` raw-pointer dance
// at call sites and removes the use-after-free / double-free risk by
// encoding the "freed exactly once" invariant in the type system.
//
// Zero cost: `KBox<T>` is `repr(transparent)` over a `NonNull<T>`, so
// it has the same machine representation as a `*mut T`. Construction
// boils down to one `kmalloc` call; `Drop` boils down to one `kfree`
// call. Field access through `Deref` / `DerefMut` is the same machine
// code as a raw pointer dereference. The compiler erases the wrapper
// to nothing.

use core::marker::PhantomData;
use core::mem::{self, MaybeUninit};
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::slice;

use crate::mm::{kmalloc, kfree};

/// Owned heap allocation of a `T`. Frees the underlying memory on drop.
///
/// `KBox<T>` is `Send` if `T` is `Send` (the underlying memory is owned),
/// and `Sync` if `T` is `Sync` (shared `&KBox<T>` only allows shared
/// access to the inner `T`).
#[repr(transparent)]
pub struct KBox<T: ?Sized> {
    ptr: NonNull<T>,
    _own: PhantomData<T>,
}

// SAFETY: KBox is the unique owner of its allocation. Send/Sync follow
// from T's bounds, exactly as alloc::Box does.
unsafe impl<T: ?Sized + Send> Send for KBox<T> {}
unsafe impl<T: ?Sized + Sync> Sync for KBox<T> {}

impl<T> KBox<T> {
    /// Allocate a `T` on the kernel heap and move `value` into it.
    /// Returns `None` if the allocator is out of memory.
    #[inline]
    pub fn try_new(value: T) -> Option<Self> {
        let raw = kmalloc(mem::size_of::<T>()) as *mut T;
        let ptr = NonNull::new(raw)?;
        // SAFETY: we just allocated; the pointer is non-null, aligned
        // (kmalloc returns 16-byte aligned blocks; T's alignment must
        // not exceed that — caller's responsibility for now), and
        // exclusively owned.
        unsafe { ptr.as_ptr().write(value); }
        Some(KBox { ptr, _own: PhantomData })
    }

    /// Allocate uninitialised storage for a `T` on the kernel heap.
    /// The caller is responsible for initialising it before reading.
    #[inline]
    pub fn try_new_uninit() -> Option<KBox<MaybeUninit<T>>> {
        let raw = kmalloc(mem::size_of::<T>()) as *mut MaybeUninit<T>;
        let ptr = NonNull::new(raw)?;
        Some(KBox { ptr, _own: PhantomData })
    }
}

impl<T> KBox<MaybeUninit<T>> {
    /// Convert `KBox<MaybeUninit<T>>` into `KBox<T>` after the caller
    /// has initialised the contents.
    ///
    /// SAFETY: caller must ensure the `MaybeUninit<T>` has been
    /// initialised with a valid `T`.
    #[inline]
    pub unsafe fn assume_init(self) -> KBox<T> {
        let raw = self.ptr.as_ptr() as *mut T;
        // Don't run our own Drop — we're transferring ownership.
        let me = mem::ManuallyDrop::new(self);
        let _ = me;
        KBox {
            ptr: unsafe { NonNull::new_unchecked(raw) },
            _own: PhantomData,
        }
    }
}

impl<T> KBox<[T]> {
    /// Allocate `n` elements on the kernel heap, uninitialised.
    /// Returns `None` if the allocator is out of memory or `n == 0`.
    #[inline]
    pub fn try_new_uninit_slice(n: usize) -> Option<KBox<[MaybeUninit<T>]>> {
        if n == 0 {
            return None;
        }
        let bytes = n.checked_mul(mem::size_of::<T>())?;
        let raw = kmalloc(bytes) as *mut MaybeUninit<T>;
        if raw.is_null() {
            return None;
        }
        // SAFETY: pointer is non-null and points to `n` elements worth
        // of memory; building a slice fat pointer is sound.
        let slice_ptr: *mut [MaybeUninit<T>] =
            unsafe { slice::from_raw_parts_mut(raw, n) as *mut _ };
        let ptr = unsafe { NonNull::new_unchecked(slice_ptr) };
        Some(KBox { ptr, _own: PhantomData })
    }

    /// Allocate `n` zeroed `T` slots and produce a `KBox<[T]>`.
    /// Requires `T: ZeroByteValid` so the all-zero bit pattern is a
    /// valid `T`. Common in net/ for u8 buffers.
    #[inline]
    pub fn try_new_zeroed_slice(n: usize) -> Option<KBox<[T]>>
    where
        T: ZeroByteValid,
    {
        let mut uninit = Self::try_new_uninit_slice(n)?;
        // SAFETY: T: ZeroByteValid means all-zeros is a valid T.
        unsafe {
            core::ptr::write_bytes(
                uninit.as_mut_ptr() as *mut u8,
                0,
                n * mem::size_of::<T>(),
            );
            Some(uninit.assume_init())
        }
    }
}

impl<T> KBox<[MaybeUninit<T>]> {
    /// Convert to an initialised slice. SAFETY: every element must be
    /// initialised.
    #[inline]
    pub unsafe fn assume_init(self) -> KBox<[T]> {
        let raw = self.ptr.as_ptr() as *mut [T];
        let me = mem::ManuallyDrop::new(self);
        let _ = me;
        KBox {
            ptr: unsafe { NonNull::new_unchecked(raw) },
            _own: PhantomData,
        }
    }
}

impl<T: ?Sized> KBox<T> {
    /// Get a raw pointer to the contents. Does not transfer ownership.
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.ptr.as_ptr() as *const T
    }

    /// Get a mutable raw pointer to the contents. Does not transfer ownership.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.ptr.as_ptr()
    }

    /// Consume the box and return the raw pointer; the caller is
    /// responsible for eventually freeing it via `from_raw` or directly
    /// via `kfree`.
    #[inline]
    pub fn into_raw(self) -> *mut T {
        let raw = self.ptr.as_ptr();
        let _ = mem::ManuallyDrop::new(self);
        raw
    }

    /// Reconstruct a `KBox` from a previously-leaked raw pointer.
    ///
    /// SAFETY: `ptr` must have come from `KBox::into_raw` (or an
    /// equivalent kmalloc allocation of exactly `size_of::<T>()` bytes
    /// for sized `T`) and must not have been freed.
    #[inline]
    pub unsafe fn from_raw(ptr: *mut T) -> Self {
        KBox {
            ptr: unsafe { NonNull::new_unchecked(ptr) },
            _own: PhantomData,
        }
    }
}

impl<T: ?Sized> Deref for KBox<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: KBox owns a valid `T` for its entire lifetime.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T: ?Sized> DerefMut for KBox<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: KBox owns a valid `T` and we hold &mut self, so no
        // other reference exists.
        unsafe { self.ptr.as_mut() }
    }
}

impl<T: ?Sized> Drop for KBox<T> {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: KBox is the unique owner of the allocation; nobody
        // else holds a reference. Drop the inner T (running its
        // Drop impl if any), then return the bytes to kmalloc.
        unsafe {
            core::ptr::drop_in_place(self.ptr.as_ptr());
            kfree(self.ptr.as_ptr() as *mut u8);
        }
    }
}

/// Marker trait: an all-zero bit pattern is a valid `Self`.
///
/// Required for `KBox::try_new_zeroed_slice` and similar zero-init
/// allocations. Implementing this for the wrong type is unsound; hence
/// it is `unsafe` to implement.
pub unsafe trait ZeroByteValid {}

unsafe impl ZeroByteValid for u8 {}
unsafe impl ZeroByteValid for u16 {}
unsafe impl ZeroByteValid for u32 {}
unsafe impl ZeroByteValid for u64 {}
unsafe impl ZeroByteValid for usize {}
unsafe impl ZeroByteValid for i8 {}
unsafe impl ZeroByteValid for i16 {}
unsafe impl ZeroByteValid for i32 {}
unsafe impl ZeroByteValid for i64 {}
unsafe impl ZeroByteValid for isize {}
