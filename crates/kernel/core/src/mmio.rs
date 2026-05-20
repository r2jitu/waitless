// kernel/mmio.rs — Typed MMIO register accessors.
//
// The dominant unsafe pattern in the driver layer is:
//
//     unsafe { ptr::write_volatile((BASE + OFFSET) as *mut u32, val) }
//     unsafe { ptr::read_volatile((BASE + OFFSET) as *const u32) }
//
// Each call site is unsafe at the type level (raw pointer, unchecked
// alignment, unchecked address) but the actual logic is "read this
// fixed offset from this device". The unsafety is in the *position*,
// not the operation — once you've validated that you have a valid
// device base pointer of the right type, every register access is sound.
//
// `mmio::ReadOnly<T>`, `WriteOnly<T>`, `ReadWrite<T>` make the position
// part of the type system. A device's register layout is described as a
// `#[repr(C)]` struct of these wrappers; the offset of each register is
// the field's offset within the struct (validated at compile time by
// the layout). Construction of a typed device handle from a base
// address is `unsafe` (one site per device); every subsequent register
// access is safe Rust:
//
//     #[repr(C)]
//     struct Pl011Regs {
//         dr:    ReadWrite<u32>,    // offset 0x00
//         _rsv0: u32,               // offset 0x04
//         _rsv1: [u32; 4],          // offset 0x08-0x14
//         fr:    ReadOnly<u32>,     // offset 0x18
//         // ...
//     }
//
//     let uart = unsafe { Pl011Regs::from_base(uart_base) };
//     uart.dr.write(c as u32);
//     while (uart.fr.read() & FR_TXFF) != 0 {}
//
// Zero cost: each accessor is `#[repr(transparent)]` over `UnsafeCell<T>`,
// so the layout matches the underlying register exactly. `read()` and
// `write()` inline to a single `ptr::read_volatile` / `ptr::write_volatile`
// — exactly the same code the manual `unsafe { ... }` blocks emitted.

use core::cell::UnsafeCell;
use core::ptr;

/// A read-only MMIO register of type `T`. `T` is typically `u8`/`u16`/
/// `u32`/`u64` for hardware registers.
#[repr(transparent)]
pub struct ReadOnly<T: Copy> {
    val: UnsafeCell<T>,
}

impl<T: Copy> ReadOnly<T> {
    #[inline(always)]
    pub fn read(&self) -> T {
        // SAFETY: ReadOnly is constructed via a typed device handle whose
        // creation is the (one) unsafe site that validates the base
        // address. The UnsafeCell allows us to read through `&self`
        // without forming a `&T` (which would need to be properly aligned
        // and not aliased). `ptr::read_volatile` performs an aligned
        // load that the compiler will not elide.
        unsafe { ptr::read_volatile(self.val.get()) }
    }
}

/// A write-only MMIO register of type `T`.
#[repr(transparent)]
pub struct WriteOnly<T: Copy> {
    val: UnsafeCell<T>,
}

impl<T: Copy> WriteOnly<T> {
    #[inline(always)]
    pub fn write(&self, value: T) {
        // SAFETY: same as ReadOnly::read.
        unsafe { ptr::write_volatile(self.val.get(), value) }
    }
}

/// A read-write MMIO register of type `T`.
#[repr(transparent)]
pub struct ReadWrite<T: Copy> {
    val: UnsafeCell<T>,
}

impl<T: Copy> ReadWrite<T> {
    #[inline(always)]
    pub fn read(&self) -> T {
        unsafe { ptr::read_volatile(self.val.get()) }
    }

    #[inline(always)]
    pub fn write(&self, value: T) {
        unsafe { ptr::write_volatile(self.val.get(), value) }
    }

    /// Read-modify-write convenience. Not atomic; intended for
    /// boot-time / single-writer init code.
    #[inline(always)]
    pub fn modify<F: FnOnce(T) -> T>(&self, f: F) {
        let v = self.read();
        self.write(f(v));
    }
}

// SAFETY: MMIO accessors are intentionally Sync. The hardware behind
// them serialises accesses; the language-level synchronisation is
// volatile (which is what these wrappers emit). Sharing the same
// device handle across cores is exactly what driver code wants.
unsafe impl<T: Copy + Send> Sync for ReadOnly<T> {}
unsafe impl<T: Copy + Send> Sync for WriteOnly<T> {}
unsafe impl<T: Copy + Send> Sync for ReadWrite<T> {}

/// Wrap a base address as a `&'static D` where `D` is a `#[repr(C)]`
/// struct of register accessors. This is the (one) unsafe entry point;
/// all subsequent register access through the returned reference is
/// safe Rust.
///
/// # Safety
///
/// Caller must ensure that
///   1. `base` is a valid MMIO address for a device whose register
///      layout matches `D`,
///   2. the device exists for the lifetime of the program (`'static`),
///   3. nothing else holds a `&mut D` to the same address (other
///      `&D` shared references are fine; the wrapper types provide
///      interior mutability via `UnsafeCell`).
#[inline(always)]
pub unsafe fn at<D>(base: u64) -> &'static D {
    // SAFETY: caller-asserted; see fn-level docs.
    unsafe { &*(base as *const D) }
}
