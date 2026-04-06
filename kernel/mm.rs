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

use crate::serial;
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
const HEAP_SIZE: usize = 16 * 1024 * 1024; // 16 MB

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

static mut FRAME_ALLOC: FrameAllocator = FrameAllocator::ZEROED;

// ============================================================================
// Address translation state
// ============================================================================

struct AddressSpace {
    hhdm_offset: u64,
    kernel_phys_base: u64,
    kernel_virt_base: u64,
}

impl AddressSpace {
    const ZEROED: Self = Self {
        hhdm_offset: 0,
        kernel_phys_base: 0,
        kernel_virt_base: 0,
    };
}

static mut ADDR_SPACE: AddressSpace = AddressSpace::ZEROED;

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

static mut HEAP: Heap = Heap::ZEROED;

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

pub fn init(info: *const BootInfo) {
    unsafe {
    let info = &*info;

    // ---- Phase 1: Compute total memory and max physical address ----
    ADDR_SPACE.hhdm_offset = info.hhdm_offset;
    ADDR_SPACE.kernel_phys_base = info.kernel_phys_base;
    ADDR_SPACE.kernel_virt_base = info.kernel_virt_base;
    FRAME_ALLOC.total_memory = 0;
    let mut max_physical_addr: u64 = 0;

    for i in 0..info.memory_map_count as usize {
        let region = &info.memory_map[i];
        if region.region_type == MEM_AVAILABLE {
            FRAME_ALLOC.total_memory += region.length;
            let end = region.base + region.length;
            if end > max_physical_addr {
                max_physical_addr = end;
            }
        }
    }

    klog!(
        "  Physical memory: {} MB (max addr {:#x})\n",
        FRAME_ALLOC.total_memory / (1024 * 1024),
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

    FRAME_ALLOC.total_frames = max_physical_addr / PAGE_SIZE;
    let bitmap_byte_size = Bitmap::byte_size(FRAME_ALLOC.total_frames);
    FRAME_ALLOC.bitmap.num_bits = FRAME_ALLOC.total_frames;

    // Find where to place the bitmap + heap.
    let needed = align_up_page(bitmap_byte_size) + HEAP_SIZE as u64;
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
    FRAME_ALLOC.bitmap.data = (ADDR_SPACE.hhdm_offset + bitmap_phys) as *mut u8;

    // Start: all frames used (0xFF = all bits set)
    FRAME_ALLOC.bitmap.fill(0xFF);
    FRAME_ALLOC.used_frames = FRAME_ALLOC.total_frames;

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
            if frame < FRAME_ALLOC.total_frames && FRAME_ALLOC.bitmap.test(frame) {
                FRAME_ALLOC.bitmap.clear(frame);
                FRAME_ALLOC.used_frames -= 1;
            }
            addr += PAGE_SIZE;
        }
    }

    // Reserve kernel image (physical) + bitmap
    FRAME_ALLOC.mark_frames_used(info.kernel_phys_base, kern_end_phys);
    let bitmap_end_phys = bitmap_phys + align_up_page(bitmap_byte_size);
    FRAME_ALLOC.mark_frames_used(bitmap_phys, bitmap_end_phys);

    klog!(
        "  Frame allocator: {} total frames, {} free frames\n",
        FRAME_ALLOC.total_frames,
        FRAME_ALLOC.total_frames - FRAME_ALLOC.used_frames
    );

    // ---- Phase 4: Set up the kernel heap ----
    let heap_phys = bitmap_end_phys;
    HEAP.start = (ADDR_SPACE.hhdm_offset + heap_phys) as *mut u8;
    HEAP.end = HEAP.start.add(HEAP_SIZE);

    // Mark heap pages as used in the frame allocator
    FRAME_ALLOC.mark_frames_used(heap_phys, heap_phys + HEAP_SIZE as u64);

    // Initialize the heap with a single large free block
    HEAP.head = HEAP.start as *mut BlockHeader;
    (*HEAP.head).size = (HEAP_SIZE - core::mem::size_of::<BlockHeader>()) as u64;
    (*HEAP.head).next = ptr::null_mut();
    (*HEAP.head).free = true;

    klog!(
        "  Heap: {} KB at phys {:#x}\n",
        HEAP_SIZE / 1024,
        heap_phys
    );
    } // unsafe
}

pub fn alloc_frame() -> u64 {
    unsafe {
        // Linear scan for the first free frame
        for i in 0..FRAME_ALLOC.total_frames {
            if !FRAME_ALLOC.bitmap.test(i) {
                FRAME_ALLOC.bitmap.set(i);
                FRAME_ALLOC.used_frames += 1;
                return i * PAGE_SIZE;
            }
        }
        klog!("mm::alloc_frame: out of physical memory!\n");
        0
    }
}

pub fn free_frame(addr: u64) {
    unsafe {
        let frame = addr / PAGE_SIZE;
        if frame >= FRAME_ALLOC.total_frames {
            return;
        }
        if FRAME_ALLOC.bitmap.test(frame) {
            FRAME_ALLOC.bitmap.clear(frame);
            FRAME_ALLOC.used_frames -= 1;
        }
    }
}

pub fn kmalloc(size: usize) -> *mut u8 {
    unsafe {
        if size == 0 {
            return ptr::null_mut();
        }

        // Align up to 16 bytes
        let size = (size + 15) & !15;

        // First-fit search
        let mut current = HEAP.head;
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

pub fn kfree(ptr: *mut u8) {
    unsafe {
        if ptr.is_null() {
            return;
        }

        let header_size = core::mem::size_of::<BlockHeader>();
        let block = ptr.sub(header_size) as *mut BlockHeader;

        // Sanity check: pointer within heap?
        let block_addr = block as *mut u8;
        if block_addr < HEAP.start || block_addr >= HEAP.end {
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
        let mut current = HEAP.head;
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
    unsafe { FRAME_ALLOC.total_memory as usize }
}

pub fn get_free_memory() -> usize {
    unsafe { ((FRAME_ALLOC.total_frames - FRAME_ALLOC.used_frames) * PAGE_SIZE) as usize }
}

pub fn phys_to_virt(phys: u64) -> *mut u8 {
    #[cfg(target_arch = "aarch64")]
    {
        phys as *mut u8
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        (ADDR_SPACE.hhdm_offset + phys) as *mut u8
    }
}

pub fn virt_to_phys(virt: *const u8) -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        virt as u64
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let addr = virt as u64;
        // Check kernel virtual range first (higher addresses than HHDM)
        if ADDR_SPACE.kernel_virt_base != 0 && addr >= ADDR_SPACE.kernel_virt_base {
            return addr - ADDR_SPACE.kernel_virt_base + ADDR_SPACE.kernel_phys_base;
        }
        if ADDR_SPACE.hhdm_offset != 0 && addr >= ADDR_SPACE.hhdm_offset {
            return addr - ADDR_SPACE.hhdm_offset;
        }
        addr // identity-mapped
    }
}
