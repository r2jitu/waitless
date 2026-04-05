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

#![no_std]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(static_mut_refs)]

use core::ptr;

// ============================================================================
// Dependencies
// ============================================================================

extern crate kernel_serial;
extern crate kernel_types;
use kernel_types::{BootInfo, MEM_AVAILABLE};

unsafe extern "C" {
    // Linker-provided symbol marking the end of the kernel image
    static _kernel_end: u8;
}

fn log_fmt(args: core::fmt::Arguments) {
    kernel_serial::serial_write_fmt(args);
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
const HEAP_SIZE: usize = 16 * 1024 * 1024; // 16 MB

// ============================================================================
// Physical frame allocator state
// ============================================================================

static mut FRAME_BITMAP: *mut u8 = ptr::null_mut();
static mut FRAME_BITMAP_SIZE: u64 = 0;
static mut TOTAL_FRAMES: u64 = 0;
static mut USED_FRAMES: u64 = 0;
static mut TOTAL_MEMORY_BYTES: u64 = 0;
static mut HHDM_OFFSET: u64 = 0;
static mut KERNEL_PHYS_BASE: u64 = 0;
static mut KERNEL_VIRT_BASE: u64 = 0;

// ============================================================================
// Bitmap helpers
// ============================================================================

unsafe fn bitmap_set(frame: u64) {
    if frame < TOTAL_FRAMES {
        let byte = &mut *FRAME_BITMAP.add((frame / 8) as usize);
        *byte |= 1 << (frame % 8);
    }
}

unsafe fn bitmap_clear(frame: u64) {
    if frame < TOTAL_FRAMES {
        let byte = &mut *FRAME_BITMAP.add((frame / 8) as usize);
        *byte &= !(1 << (frame % 8));
    }
}

unsafe fn bitmap_test(frame: u64) -> bool {
    if frame < TOTAL_FRAMES {
        let byte = *FRAME_BITMAP.add((frame / 8) as usize);
        (byte & (1 << (frame % 8))) != 0
    } else {
        true // Out-of-range frames are considered "in use"
    }
}

/// Mark a range of frames as used
unsafe fn mark_frames_used(start_addr: u64, end_addr: u64) {
    let start_frame = start_addr / PAGE_SIZE;
    let mut end_frame = (end_addr + PAGE_SIZE - 1) / PAGE_SIZE;
    if end_frame > TOTAL_FRAMES {
        end_frame = TOTAL_FRAMES;
    }
    for i in start_frame..end_frame {
        if !bitmap_test(i) {
            bitmap_set(i);
            USED_FRAMES += 1;
        }
    }
}

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

static mut HEAP_START: *mut u8 = ptr::null_mut();
static mut HEAP_END: *mut u8 = ptr::null_mut();
static mut HEAP_HEAD: *mut BlockHeader = ptr::null_mut();

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

pub fn mm_init(info: *const BootInfo) {
    unsafe {
    let info = &*info;

    // ---- Phase 1: Compute total memory and max physical address ----
    HHDM_OFFSET = info.hhdm_offset;
    KERNEL_PHYS_BASE = info.kernel_phys_base;
    KERNEL_VIRT_BASE = info.kernel_virt_base;
    TOTAL_MEMORY_BYTES = 0;
    let mut max_physical_addr: u64 = 0;

    for i in 0..info.memory_map_count as usize {
        let region = &info.memory_map[i];
        if region.region_type == MEM_AVAILABLE {
            TOTAL_MEMORY_BYTES += region.length;
            let end = region.base + region.length;
            if end > max_physical_addr {
                max_physical_addr = end;
            }
        }
    }

    klog!(
        "  Physical memory: {} MB (max addr {:#x})\n",
        TOTAL_MEMORY_BYTES / (1024 * 1024),
        max_physical_addr
    );

    // ---- Phase 2: Set up frame bitmap ----
    // When the kernel is linked in the higher half (Limine boot),
    // _kernel_end is a virtual address like 0xFFFFFFFF801xxxxx.
    // Compute the physical end using the phys/virt base from BootInfo.
    let kern_end_ptr = &raw const _kernel_end as u64;
    let kern_end_phys = if info.kernel_virt_base != 0 {
        info.kernel_phys_base + (kern_end_ptr - info.kernel_virt_base)
    } else {
        kern_end_ptr
    };

    TOTAL_FRAMES = max_physical_addr / PAGE_SIZE;
    FRAME_BITMAP_SIZE = (TOTAL_FRAMES + 7) / 8;

    // Find where to place the bitmap + heap.
    let needed = align_up_page(FRAME_BITMAP_SIZE) + HEAP_SIZE as u64;
    let mut placement_phys: u64 = 0;

    if info.kernel_virt_base != 0 {
        // Higher-half (Limine): find the largest available region
        let mut best_size: u64 = 0;
        for i in 0..info.memory_map_count as usize {
            let region = &info.memory_map[i];
            if region.region_type != MEM_AVAILABLE {
                continue;
            }
            let rbase = align_up_page(region.base);
            let rend = (region.base + region.length) & !(PAGE_SIZE - 1);
            if rend > rbase && (rend - rbase) > best_size && (rend - rbase) >= needed {
                best_size = rend - rbase;
                placement_phys = rbase;
            }
        }
    }

    if placement_phys == 0 {
        // Identity-mapped boot or fallback: place after kernel
        placement_phys = align_up_page(kern_end_phys);
    }

    let bitmap_phys = placement_phys;
    FRAME_BITMAP = (HHDM_OFFSET + bitmap_phys) as *mut u8;

    // Start: all frames used (0xFF = all bits set)
    ptr::write_bytes(FRAME_BITMAP, 0xFF, FRAME_BITMAP_SIZE as usize);
    USED_FRAMES = TOTAL_FRAMES;

    // ---- Phase 3: Free available regions from memory map ----
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
            if frame < TOTAL_FRAMES && bitmap_test(frame) {
                bitmap_clear(frame);
                USED_FRAMES -= 1;
            }
            addr += PAGE_SIZE;
        }
    }

    // Reserve kernel image (physical) + bitmap
    mark_frames_used(info.kernel_phys_base, kern_end_phys);
    let bitmap_end_phys = bitmap_phys + align_up_page(FRAME_BITMAP_SIZE);
    mark_frames_used(bitmap_phys, bitmap_end_phys);

    klog!(
        "  Frame allocator: {} total frames, {} free frames\n",
        TOTAL_FRAMES,
        TOTAL_FRAMES - USED_FRAMES
    );

    // ---- Phase 4: Set up the kernel heap ----
    let heap_phys = bitmap_end_phys;
    HEAP_START = (HHDM_OFFSET + heap_phys) as *mut u8;
    HEAP_END = HEAP_START.add(HEAP_SIZE);

    // Mark heap pages as used in the frame allocator
    mark_frames_used(heap_phys, heap_phys + HEAP_SIZE as u64);

    // Initialize the heap with a single large free block
    HEAP_HEAD = HEAP_START as *mut BlockHeader;
    (*HEAP_HEAD).size = (HEAP_SIZE - core::mem::size_of::<BlockHeader>()) as u64;
    (*HEAP_HEAD).next = ptr::null_mut();
    (*HEAP_HEAD).free = true;

    klog!(
        "  Heap: {} KB at phys {:#x}\n",
        HEAP_SIZE / 1024,
        heap_phys
    );
    } // unsafe
}

pub fn mm_alloc_frame() -> u64 {
    unsafe {
        // Linear scan for the first free frame
        for i in 0..TOTAL_FRAMES {
            if !bitmap_test(i) {
                bitmap_set(i);
                USED_FRAMES += 1;
                return i * PAGE_SIZE;
            }
        }
        klog!("mm::alloc_frame: out of physical memory!\n");
        0
    }
}

pub fn mm_free_frame(addr: u64) {
    unsafe {
        let frame = addr / PAGE_SIZE;
        if frame >= TOTAL_FRAMES {
            return;
        }
        if bitmap_test(frame) {
            bitmap_clear(frame);
            USED_FRAMES -= 1;
        }
    }
}

pub fn mm_kmalloc(size: usize) -> *mut u8 {
    unsafe {
        if size == 0 {
            return ptr::null_mut();
        }

        // Align up to 16 bytes
        let size = (size + 15) & !15;

        // First-fit search
        let mut current = HEAP_HEAD;
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

        klog!("mm::kmalloc: out of heap memory (requested {} bytes)!\n", size);
        ptr::null_mut()
    }
}

pub fn mm_kfree(ptr: *mut u8) {
    unsafe {
        if ptr.is_null() {
            return;
        }

        let header_size = core::mem::size_of::<BlockHeader>();
        let block = ptr.sub(header_size) as *mut BlockHeader;

        // Sanity check: pointer within heap?
        let block_addr = block as *mut u8;
        if block_addr < HEAP_START || block_addr >= HEAP_END {
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
        let mut current = HEAP_HEAD;
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

pub fn mm_get_total_memory() -> usize {
    unsafe { TOTAL_MEMORY_BYTES as usize }
}

pub fn mm_get_free_memory() -> usize {
    unsafe { ((TOTAL_FRAMES - USED_FRAMES) * PAGE_SIZE) as usize }
}

pub fn mm_phys_to_virt(phys: u64) -> *mut u8 {
    #[cfg(target_arch = "aarch64")]
    {
        phys as *mut u8
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        (HHDM_OFFSET + phys) as *mut u8
    }
}

pub fn mm_virt_to_phys(virt: *const u8) -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        virt as u64
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let addr = virt as u64;
        // Check kernel virtual range first (higher addresses than HHDM)
        if KERNEL_VIRT_BASE != 0 && addr >= KERNEL_VIRT_BASE {
            return addr - KERNEL_VIRT_BASE + KERNEL_PHYS_BASE;
        }
        if HHDM_OFFSET != 0 && addr >= HHDM_OFFSET {
            return addr - HHDM_OFFSET;
        }
        addr // identity-mapped
    }
}
