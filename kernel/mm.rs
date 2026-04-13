// kernel/mm.rs -- Memory management in Rust
//
// Two-tier memory management:
//
// 1. Physical frame allocator:
//    A bitmap where each bit represents a 4KB page frame. Bit=1 means used.
//    The bitmap lives immediately after _kernel_end (or in the largest
//    available region for Limine higher-half boot).
//
// 2. Kernel heap allocator:
//    A classic free-list allocator with block headers. Each block has a
//    header containing {size, next pointer, free flag}. kmalloc() walks the
//    free list (first-fit), splitting if the block is significantly larger
//    than requested. kfree() marks the block as free and coalesces with
//    physically adjacent free blocks.
//
//    The heap starts after the frame bitmap and grows upward. We pre-allocate
//    a fixed heap region (16MB) from the available physical memory.

use core::ptr;

// ============================================================================
// Dependencies
// ============================================================================

use crate::once::InitOnce;
use crate::serial;
use crate::sync::Spinlock;
use crate::types::{BootInfo, MEM_AVAILABLE};

unsafe extern "C" {
    // Linker-provided symbol marking the end of the kernel image
    static _kernel_end: u8;
}

fn log_fmt(args: core::fmt::Arguments) {
    serial::write_fmt(args);
}

macro_rules! klog {
    ($($arg:tt)*) => {
        log_fmt(core::format_args!($($arg)*))
    };
}

// ============================================================================
// Constants
// ============================================================================

const PAGE_SIZE: u64 = 4096;
const MIN_BLOCK_SIZE: usize = 16;
const HEAP_SIZE: usize = 32 * 1024 * 1024; // 32 MB

// ============================================================================
// Bitmap type — bounds-checked access to a raw pointer + bit count
// ============================================================================

struct Bitmap {
    data: *mut u8,
    num_bits: u64,
}

impl Bitmap {
    const ZEROED: Self = Self {
        data: ptr::null_mut(),
        num_bits: 0,
    };

    /// Returns the number of bytes needed to store `num_bits` bits.
    fn byte_size(num_bits: u64) -> u64 {
        (num_bits + 7) / 8
    }

    fn set(&mut self, bit: u64) {
        unsafe {
            if bit < self.num_bits {
                let byte = &mut *self.data.add((bit / 8) as usize);
                *byte |= 1 << (bit % 8);
            }
        }
    }

    fn clear(&mut self, bit: u64) {
        unsafe {
            if bit < self.num_bits {
                let byte = &mut *self.data.add((bit / 8) as usize);
                *byte &= !(1 << (bit % 8));
            }
        }
    }

    fn test(&self, bit: u64) -> bool {
        unsafe {
            if bit < self.num_bits {
                let byte = *self.data.add((bit / 8) as usize);
                (byte & (1 << (bit % 8))) != 0
            } else {
                true // Out-of-range bits are considered "set"
            }
        }
    }

    /// Fill all bytes with `val` (0xFF = all set, 0x00 = all clear).
    unsafe fn fill(&mut self, val: u8) {
        unsafe {
            ptr::write_bytes(self.data, val, Bitmap::byte_size(self.num_bits) as usize);
        }
    }
}

// ============================================================================
// Frame allocator state
// ============================================================================

struct FrameAllocator {
    bitmap: Bitmap,
    total_frames: u64,
    used_frames: u64,
    total_memory: u64,
}

impl FrameAllocator {
    const ZEROED: Self = Self {
        bitmap: Bitmap::ZEROED,
        total_frames: 0,
        used_frames: 0,
        total_memory: 0,
    };

    /// Mark a range of frames as used (by physical address range).
    unsafe fn mark_frames_used(&mut self, start_addr: u64, end_addr: u64) {
        let start_frame = start_addr / PAGE_SIZE;
        let mut end_frame = (end_addr + PAGE_SIZE - 1) / PAGE_SIZE;
        if end_frame > self.total_frames {
            end_frame = self.total_frames;
        }
        for i in start_frame..end_frame {
            if !self.bitmap.test(i) {
                self.bitmap.set(i);
                self.used_frames += 1;
            }
        }
    }
}

// SAFETY: FrameAllocator owns a `*mut u8` (the bitmap data pointer)
// pointing into kernel-owned memory. The pointer is never aliased; only
// the lock holder accesses the bitmap. Send is sound because the lock
// transfers exclusive access between cores.
unsafe impl Send for FrameAllocator {}

/// Frame allocator behind a spinlock. The previous `static mut
/// FRAME_ALLOC` was a Tier-1 footgun from the original safety audit:
/// every alloc/free path was unlocked, so concurrent post-boot
/// allocation from any AP would race the bitmap.
static FRAME_ALLOC: Spinlock<FrameAllocator> = Spinlock::new(FrameAllocator::ZEROED);

// ============================================================================
// Address translation state
// ============================================================================

// Fields are only consumed by phys_to_virt/virt_to_phys on x86_64; on
// aarch64 the translation is identity-mapped and the fields are dead.
#[allow(dead_code)]
struct AddressSpace {
    hhdm_offset: u64,
    kernel_phys_base: u64,
    kernel_virt_base: u64,
}

/// Address space configuration. Init once during boot, read-only
/// thereafter; no lock needed.
static ADDR_SPACE: InitOnce<AddressSpace> = InitOnce::new();

// ============================================================================
// Kernel heap allocator
// ============================================================================

/// Block header for the heap free-list allocator.
/// Must be exactly 24 bytes so payload is 16-byte aligned.
#[repr(C)]
struct BlockHeader {
    size: u64,              // Size of usable region (excluding header)
    next: *mut BlockHeader, // Next block in physical memory order
    free: bool,             // true if this block is available
    _padding: [u8; 7],     // Pad to 24 bytes
}

const _: () = assert!(core::mem::size_of::<BlockHeader>() == 24);

struct Heap {
    start: *mut u8,
    end: *mut u8,
    head: *mut BlockHeader,
}

impl Heap {
    const ZEROED: Self = Self {
        start: ptr::null_mut(),
        end: ptr::null_mut(),
        head: ptr::null_mut(),
    };
}

// SAFETY: Heap owns raw pointers (start/end/head). The pointers are
// never aliased; only the lock holder mutates the free list. Send is
// sound because the lock transfers exclusive access between cores.
unsafe impl Send for Heap {}

/// Kernel heap behind a spinlock. Same Tier-1 fix as FRAME_ALLOC: any
/// concurrent kmalloc/kfree from APs would race the free-list pointers.
static HEAP: Spinlock<Heap> = Spinlock::new(Heap::ZEROED);

// ============================================================================
// Helper
// ============================================================================

#[inline]
fn align_up_page(val: u64) -> u64 {
    (val + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

// ============================================================================
// Public API
// ============================================================================

/// Compute the physical end address of the kernel image. Handles both
/// identity-mapped boot (kern_end_ptr == phys) and higher-half boot
/// (Limine: virt = phys + offset).
fn kernel_end_phys(info: &BootInfo) -> u64 {
    let kern_end_ptr = &raw const _kernel_end as u64;
    if info.kernel_virt_base != 0 {
        info.kernel_phys_base + (kern_end_ptr - info.kernel_virt_base)
    } else {
        kern_end_ptr
    }
}

/// Choose where to place the frame bitmap and heap given a memory map.
/// Identity-mapped boot puts them right after the kernel image; higher-half
/// boots (Limine) search the memory map for the largest available region
/// with enough space since the kernel image may live outside main RAM.
fn pick_placement_phys(info: &BootInfo, kern_end_phys: u64, needed: u64) -> u64 {
    let kern_end_in_ram = (0..info.memory_map_count as usize).any(|i| {
        let r = &info.memory_map[i];
        r.region_type == MEM_AVAILABLE
            && kern_end_phys > r.base
            && kern_end_phys <= r.base + r.length
    });

    if info.kernel_virt_base != 0 || !kern_end_in_ram {
        let mut best_size: u64 = 0;
        let mut placement: u64 = 0;
        for i in 0..info.memory_map_count as usize {
            let region = &info.memory_map[i];
            if region.region_type != MEM_AVAILABLE {
                continue;
            }
            let rbase = align_up_page(region.base);
            let rend = (region.base + region.length) & !(PAGE_SIZE - 1);
            if rend > rbase && (rend - rbase) > best_size && (rend - rbase) >= needed {
                best_size = rend - rbase;
                placement = rbase;
            }
        }
        if placement != 0 {
            return placement;
        }
    }

    // Identity-mapped boot fallback: bitmap+heap go right after the kernel.
    align_up_page(kern_end_phys)
}

/// Initialise the frame allocator from the boot memory map. Returns the
/// physical address where the heap should be placed (immediately after the
/// bitmap). Reserves the kernel image and bitmap in the allocator before
/// returning.
fn init_frame_allocator(info: &BootInfo, kern_end_phys: u64) -> u64 {
    let mut fa = FRAME_ALLOC.lock();
    fa.total_memory = 0;
    let mut max_physical_addr: u64 = 0;

    for i in 0..info.memory_map_count as usize {
        let region = &info.memory_map[i];
        if region.region_type == MEM_AVAILABLE {
            fa.total_memory += region.length;
            let end = region.base + region.length;
            if end > max_physical_addr {
                max_physical_addr = end;
            }
        }
    }

    klog!(
        "  Physical memory: {} MB (max addr {:#x})\n",
        fa.total_memory / (1024 * 1024),
        max_physical_addr
    );

    fa.total_frames = max_physical_addr / PAGE_SIZE;
    let bitmap_byte_size = Bitmap::byte_size(fa.total_frames);
    fa.bitmap.num_bits = fa.total_frames;

    let needed = align_up_page(bitmap_byte_size) + HEAP_SIZE as u64;
    let bitmap_phys = pick_placement_phys(info, kern_end_phys, needed);
    fa.bitmap.data = (info.hhdm_offset + bitmap_phys) as *mut u8;

    // Start: all frames used (0xFF = all bits set), then free available regions.
    unsafe { fa.bitmap.fill(0xFF); }
    fa.used_frames = fa.total_frames;

    for i in 0..info.memory_map_count as usize {
        let region = &info.memory_map[i];
        if region.region_type != MEM_AVAILABLE {
            continue;
        }
        let start = align_up_page(region.base);
        let end = (region.base + region.length) & !(PAGE_SIZE - 1);
        let mut addr = start;
        while addr < end {
            let frame = addr / PAGE_SIZE;
            if frame < fa.total_frames && fa.bitmap.test(frame) {
                fa.bitmap.clear(frame);
                fa.used_frames -= 1;
            }
            addr += PAGE_SIZE;
        }
    }

    // Reserve kernel image + bitmap.
    let bitmap_end_phys = bitmap_phys + align_up_page(bitmap_byte_size);
    unsafe {
        fa.mark_frames_used(info.kernel_phys_base, kern_end_phys);
        fa.mark_frames_used(bitmap_phys, bitmap_end_phys);
        // Reserve heap pages now while we still hold the frame-allocator lock.
        fa.mark_frames_used(bitmap_end_phys, bitmap_end_phys + HEAP_SIZE as u64);
    }

    klog!(
        "  Frame allocator: {} total frames, {} free frames\n",
        fa.total_frames,
        fa.total_frames - fa.used_frames
    );

    bitmap_end_phys
}

/// Set up the kernel heap as a single large free block at `heap_phys`.
fn init_heap(hhdm_offset: u64, heap_phys: u64) {
    let heap_start = (hhdm_offset + heap_phys) as *mut u8;
    let mut heap = HEAP.lock();
    heap.start = heap_start;
    // SAFETY: heap_start points to HEAP_SIZE bytes that init_frame_allocator
    // already reserved in the frame allocator.
    unsafe {
        heap.end = heap.start.add(HEAP_SIZE);
        heap.head = heap.start as *mut BlockHeader;
        (*heap.head).size = (HEAP_SIZE - core::mem::size_of::<BlockHeader>()) as u64;
        (*heap.head).next = ptr::null_mut();
        (*heap.head).free = true;
    }

    klog!(
        "  Heap: {} KB at phys {:#x}\n",
        HEAP_SIZE / 1024,
        heap_phys
    );
}

pub fn init(info: *const BootInfo) {
    // SAFETY: caller passes a valid BootInfo pointer that lives for the
    // duration of init. Init runs single-threaded on the BSP before any
    // AP starts, so the locks below are taken without contention.
    let info = unsafe { &*info };

    ADDR_SPACE.init(AddressSpace {
        hhdm_offset: info.hhdm_offset,
        kernel_phys_base: info.kernel_phys_base,
        kernel_virt_base: info.kernel_virt_base,
    });

    let kern_end_phys = kernel_end_phys(info);
    let heap_phys = init_frame_allocator(info, kern_end_phys);
    init_heap(info.hhdm_offset, heap_phys);
}

pub fn alloc_frame() -> u64 {
    let mut fa = FRAME_ALLOC.lock();
    // Linear scan for the first free frame
    for i in 0..fa.total_frames {
        if !fa.bitmap.test(i) {
            fa.bitmap.set(i);
            fa.used_frames += 1;
            return i * PAGE_SIZE;
        }
    }
    klog!("mm::alloc_frame: out of physical memory!\n");
    0
}

/// Allocate `count` contiguous physical pages. Returns physical address or 0 on failure.
pub fn alloc_pages(count: usize) -> u64 {
    let mut fa = FRAME_ALLOC.lock();
    let total = fa.total_frames as usize;
    'outer: for start in 0..total {
        if start + count > total {
            break;
        }
        for j in 0..count {
            if fa.bitmap.test((start + j) as u64) {
                continue 'outer;
            }
        }
        // Found contiguous run
        for j in 0..count {
            fa.bitmap.set((start + j) as u64);
        }
        fa.used_frames += count as u64;
        return (start as u64) * PAGE_SIZE;
    }
    klog!("mm::alloc_pages: out of physical memory!\n");
    0
}

pub fn free_frame(addr: u64) {
    let mut fa = FRAME_ALLOC.lock();
    let frame = addr / PAGE_SIZE;
    if frame >= fa.total_frames {
        return;
    }
    if fa.bitmap.test(frame) {
        fa.bitmap.clear(frame);
        fa.used_frames -= 1;
    }
}

pub fn kmalloc(size: usize) -> *mut u8 {
    if size == 0 {
        return ptr::null_mut();
    }

    // Align up to 16 bytes
    let size = (size + 15) & !15;

    let heap = HEAP.lock();
    // SAFETY: hold the lock; nobody else mutates heap.head or any block.
    unsafe {
        // First-fit search
        let mut current = heap.head;
        while !current.is_null() {
            if (*current).free && (*current).size >= size as u64 {
                // Split the block if it's significantly larger
                let header_size = core::mem::size_of::<BlockHeader>();
                if (*current).size >= (size + header_size + MIN_BLOCK_SIZE) as u64 {
                    let new_block = (current as *mut u8).add(header_size + size) as *mut BlockHeader;
                    (*new_block).size = (*current).size - size as u64 - header_size as u64;
                    (*new_block).next = (*current).next;
                    (*new_block).free = true;

                    (*current).size = size as u64;
                    (*current).next = new_block;
                }

                (*current).free = false;

                // Return pointer just past the header
                return (current as *mut u8).add(header_size);
            }
            current = (*current).next;
        }
    }

    klog!("mm::kmalloc: out of heap memory (requested {} bytes)!\n", size);
    ptr::null_mut()
}

pub fn kfree(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }

    let heap = HEAP.lock();
    // SAFETY: hold the lock; nobody else mutates the free list.
    unsafe {
        let header_size = core::mem::size_of::<BlockHeader>();
        let block = ptr.sub(header_size) as *mut BlockHeader;

        // Sanity check: pointer within heap?
        let block_addr = block as *mut u8;
        if block_addr < heap.start || block_addr >= heap.end {
            klog!("mm::kfree: pointer outside the heap!\n");
            return;
        }

        if (*block).free {
            klog!("mm::kfree: double free detected!\n");
            return;
        }

        (*block).free = true;

        // Coalesce with next block if free
        if !(*block).next.is_null() && (*(*block).next).free {
            (*block).size += header_size as u64 + (*(*block).next).size;
            (*block).next = (*(*block).next).next;
        }

        // Coalesce with previous block if free (O(n) walk)
        let mut prev: *mut BlockHeader = ptr::null_mut();
        let mut current = heap.head;
        while !current.is_null() && current != block {
            prev = current;
            current = (*current).next;
        }
        if !prev.is_null() && (*prev).free {
            (*prev).size += header_size as u64 + (*block).size;
            (*prev).next = (*block).next;
        }
    }
}

pub fn get_total_memory() -> usize {
    FRAME_ALLOC.lock().total_memory as usize
}

pub fn get_free_memory() -> usize {
    let fa = FRAME_ALLOC.lock();
    ((fa.total_frames - fa.used_frames) * PAGE_SIZE) as usize
}

pub fn phys_to_virt(phys: u64) -> *mut u8 {
    #[cfg(target_arch = "aarch64")]
    {
        phys as *mut u8
    }
    #[cfg(target_arch = "x86_64")]
    {
        (ADDR_SPACE.get().hhdm_offset + phys) as *mut u8
    }
}

pub fn virt_to_phys(virt: *const u8) -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        virt as u64
    }
    #[cfg(target_arch = "x86_64")]
    {
        let addr = virt as u64;
        let asp = ADDR_SPACE.get();
        // Check kernel virtual range first (higher addresses than HHDM)
        if asp.kernel_virt_base != 0 && addr >= asp.kernel_virt_base {
            return addr - asp.kernel_virt_base + asp.kernel_phys_base;
        }
        if asp.hhdm_offset != 0 && addr >= asp.hhdm_offset {
            return addr - asp.hhdm_offset;
        }
        addr // identity-mapped
    }
}
