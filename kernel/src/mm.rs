// Memory management: frame bitmap + talc-backed heap.
//
// Frame bitmap: bit per 4 KB page (1 = used). Placed immediately after
// `_kernel_end`, or in the largest available region for Limine
// higher-half boot.
//
// Heap: `talc` (segregated-free-list) behind a `Spinlock`, claimed
// from whatever's left in the chosen memory region after the bitmap
// and `FRAME_RESERVE`. Dynamically sized at boot — a 128 MB VM
// gets a ~108 MB heap, a 4 GB instance gets ~3.97 GB.

use core::alloc::Layout;
use core::ptr::{self, NonNull};

#[cfg(target_os = "none")]
use core::alloc::GlobalAlloc;

use talc::{ErrOnOom, Span, Talc};

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
/// Reserve subtracted from the chosen heap region after the
/// kernel image and bitmap, to leave room for the frame allocator
/// (driver DMA buffers, virtio rings, page tables, per-core stacks
/// not already covered in the kernel image). Whatever's left in
/// the region after the bitmap + this reserve becomes the talc
/// heap.
///
/// The actual draw on `alloc_frame` is bounded — the NIC driver's
/// RX buffer pool (`RX_BUFFERS × BUFFER_SIZE × MAX_QP`) dominates
/// at ~4 MB worst-case; everything else is single-digit MB. 16 MB
/// is comfortable headroom and keeps the reserve a constant
/// regardless of total RAM (a percentage-based reserve would waste
/// >100 MB on a multi-GB instance for no gain).
const FRAME_RESERVE: u64 = 16 * 1024 * 1024;

/// Minimum heap size we'll boot with. If `available_region -
/// bitmap - FRAME_RESERVE < HEAP_MIN_SIZE`, init aborts loudly
/// instead of handing talc a useless tiny heap. Sized to cover the
/// runtime's per-worker arenas + minimal listener state on a
/// single-core boot — apps that bind many UDP sockets need
/// considerably more, but those don't run on a 16 MB VM anyway.
const HEAP_MIN_SIZE: usize = 8 * 1024 * 1024;

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

/// Address space configuration captured from the bootloader (Limine
/// on x86_64, a zero-filled instance on aarch64). `phys_to_virt` and
/// `virt_to_phys` consume the three fields on x86_64 to translate
/// across the higher-half direct map; on aarch64 the kernel uses an
/// identity map and the translation functions just return their input,
/// so the fields are read but never acted on.
///
/// The `#[allow(dead_code)]` covers the aarch64 build only — on that
/// target the struct is populated but the fields are never read. It
/// stays because removing it would force the init code to become
/// cfg-gated too, which is more churn for less clarity.
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

/// Kernel heap behind a spinlock. `Talc<ErrOnOom>` is a segregated
/// free-list allocator; `claim()` is called once during `init_heap`
/// with the pre-reserved heap span. Every downstream allocation
/// (GlobalAlloc path + legacy `kmalloc`/`kfree`) funnels through
/// this single static.
static HEAP: Spinlock<Talc<ErrOnOom>> = Spinlock::new(Talc::new(ErrOnOom));

/// Prefix size for legacy `kmalloc`/`kfree`. The C-style API
/// doesn't carry the original allocation size at free time, so we
/// stash the `size` as a leading `usize` and shift the returned
/// pointer past it. 16 bytes of padding keeps the user-visible
/// pointer aligned to 16 bytes — the previous allocator's guarantee
/// that some callers (e.g. virtio-net DMA buffer carving) rely on.
///
/// Only paid by `kmalloc`/`kfree` callers. The GlobalAlloc path
/// (used by `alloc::boxed::Box`, `alloc::vec::Vec`, etc.) knows the
/// layout at free time and pays zero overhead.
const KMALLOC_PREFIX: usize = 16;

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

/// Choose where to place the frame bitmap and heap, and how big
/// the heap can be in that region. Identity-mapped boot puts them
/// right after the kernel image (using whatever's left in the
/// kernel's region); higher-half boots search the memory map for
/// the largest available region since the kernel image may live
/// outside main RAM. Returns `(placement_phys, region_end_phys)`
/// — caller carves bitmap + heap out of `[placement, region_end)`.
fn pick_placement_phys(info: &BootInfo, kern_end_phys: u64) -> (u64, u64) {
    let mut kern_region_end: u64 = 0;
    for i in 0..info.memory_map_count as usize {
        let r = &info.memory_map[i];
        if r.region_type == MEM_AVAILABLE
            && kern_end_phys > r.base
            && kern_end_phys <= r.base + r.length
        {
            kern_region_end = (r.base + r.length) & !(PAGE_SIZE - 1);
            break;
        }
    }
    let kern_end_in_ram = kern_region_end != 0;

    if info.kernel_virt_base != 0 || !kern_end_in_ram {
        let mut best_size: u64 = 0;
        let mut placement: u64 = 0;
        let mut placement_end: u64 = 0;
        for i in 0..info.memory_map_count as usize {
            let region = &info.memory_map[i];
            if region.region_type != MEM_AVAILABLE {
                continue;
            }
            let rbase = align_up_page(region.base);
            let rend = (region.base + region.length) & !(PAGE_SIZE - 1);
            if rend > rbase && (rend - rbase) > best_size {
                best_size = rend - rbase;
                placement = rbase;
                placement_end = rend;
            }
        }
        if placement != 0 {
            return (placement, placement_end);
        }
    }

    // Identity-mapped boot: bitmap+heap go right after the kernel,
    // ending at the same region boundary the kernel lives in.
    (align_up_page(kern_end_phys), kern_region_end)
}

/// Initialise the frame allocator from the boot memory map.
/// Returns `(heap_phys, heap_size)` — the heap is sized at boot
/// from whatever's left in the chosen region after the bitmap and
/// the FRAME_RESERVE driver-buffer reserve. Reserves the kernel
/// image, bitmap, and the picked heap span in the bitmap before
/// returning so they don't leak into `alloc_frame`.
fn init_frame_allocator(info: &BootInfo, kern_end_phys: u64) -> (u64, usize) {
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

    let (bitmap_phys, region_end) = pick_placement_phys(info, kern_end_phys);
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
    // Heap consumes everything remaining in this region, minus
    // FRAME_RESERVE for the frame allocator's own page-grain
    // allocations. Page-aligned downward so talc's claim is
    // well-formed.
    let heap_phys = bitmap_end_phys;
    let heap_end = if region_end > heap_phys.saturating_add(FRAME_RESERVE) {
        (region_end - FRAME_RESERVE) & !(PAGE_SIZE - 1)
    } else {
        // Tiny region — fall back to "everything after the bitmap"
        // and let the HEAP_MIN_SIZE check below catch the case.
        region_end & !(PAGE_SIZE - 1)
    };
    let heap_size = heap_end.saturating_sub(heap_phys) as usize;
    unsafe {
        fa.mark_frames_used(info.kernel_phys_base, kern_end_phys);
        fa.mark_frames_used(bitmap_phys, bitmap_end_phys);
        // Reserve heap pages now while we still hold the frame-allocator lock.
        fa.mark_frames_used(heap_phys, heap_phys + heap_size as u64);
    }

    klog!(
        "  Frame allocator: {} total frames, {} free frames\n",
        fa.total_frames,
        fa.total_frames - fa.used_frames
    );

    (heap_phys, heap_size)
}

/// Hand the pre-reserved heap span to `talc`. Called once during boot
/// on the BSP before any AP starts, so the lock below is uncontended.
fn init_heap(hhdm_offset: u64, heap_phys: u64, heap_size: usize) {
    if heap_size < HEAP_MIN_SIZE {
        klog!(
            "  Heap: refusing to claim {} KB (< HEAP_MIN_SIZE = {} KB) — \
             increase VM RAM\n",
            heap_size / 1024,
            HEAP_MIN_SIZE / 1024,
        );
        return;
    }
    let heap_start = (hhdm_offset + heap_phys) as *mut u8;
    // SAFETY: `heap_start .. heap_start + heap_size` is a contiguous
    // range of valid, exclusive, unused memory — `init_frame_allocator`
    // just reserved those pages in the frame bitmap, and nothing else
    // has handed them out. `Span::from_base_size` is const + infallible;
    // `claim` is sound given that precondition.
    let span = Span::from_base_size(heap_start, heap_size);
    let mut heap = HEAP.lock();
    unsafe {
        if heap.claim(span).is_err() {
            klog!("  Heap: talc::claim failed ({} bytes)!\n", heap_size);
            return;
        }
    }
    drop(heap);

    klog!(
        "  Heap: {} MB at phys {:#x}\n",
        heap_size / (1024 * 1024),
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
    let (heap_phys, heap_size) = init_frame_allocator(info, kern_end_phys);
    init_heap(info.hhdm_offset, heap_phys, heap_size);
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

// ============================================================================
// Global allocator
// ============================================================================
//
// `#[global_allocator]` forwards the GlobalAlloc trait (used by
// `alloc::boxed::Box`, `alloc::vec::Vec`, RustCrypto internals, …)
// into `HEAP.lock().malloc/free`. The layout is known at both alloc
// and dealloc time so no side-channel size tracking is needed here.
//
// Only compiled for bare-metal targets; native host builds use libstd's
// default allocator via std. `#[used]` keeps the linker from GC'ing
// the symbol since rustc's `#[global_allocator]` machinery resolves
// it at driver level rather than via a normal symbol reference.

#[cfg(target_os = "none")]
pub struct KernelAllocator;

#[cfg(target_os = "none")]
unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() == 0 {
            // `talc::malloc` requires non-zero size; the GlobalAlloc
            // contract lets us return any non-null well-aligned pointer
            // for ZSTs. A dangling pointer at the requested alignment
            // is both sound and ubiquitous (alloc::alloc::alloc does
            // the same).
            return core::ptr::without_provenance_mut(layout.align());
        }
        let mut heap = HEAP.lock();
        // SAFETY: size is non-zero (checked above); the spinlock grants
        // exclusive access to the allocator state.
        match unsafe { heap.malloc(layout) } {
            Ok(nn) => nn.as_ptr(),
            Err(()) => {
                drop(heap);
                klog!(
                    "mm::alloc: OOM ({} bytes, align {})\n",
                    layout.size(),
                    layout.align()
                );
                ptr::null_mut()
            }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() == 0 {
            return;
        }
        let Some(nn) = NonNull::new(ptr) else { return };
        let mut heap = HEAP.lock();
        // SAFETY: caller guarantees `ptr` came from a previous `alloc`
        // with a matching `layout`; the spinlock grants exclusive access.
        unsafe { heap.free(nn, layout) };
    }
}

#[cfg(target_os = "none")]
#[global_allocator]
#[used]
pub static GLOBAL_ALLOCATOR: KernelAllocator = KernelAllocator;

/// Layout the legacy `kmalloc` path uses. The 16-byte prefix stores
/// the user-requested size so `kfree` can reconstruct the exact layout
/// that was handed to `talc::malloc`.
fn kmalloc_layout(user_size: usize) -> Option<Layout> {
    let total = user_size.checked_add(KMALLOC_PREFIX)?;
    Layout::from_size_align(total, KMALLOC_PREFIX).ok()
}

/// Legacy size-only malloc, retained for DMA-buffer call sites in
/// `drivers/virtio_net.rs` and a handful of wrapper types that
/// predate `#[global_allocator]`. Stores the requested size in a
/// 16-byte prefix so `kfree` can recover the layout.
///
/// Prefer `alloc::boxed::Box` / `alloc::alloc::alloc` for new code —
/// those skip the prefix overhead.
pub fn kmalloc(size: usize) -> *mut u8 {
    if size == 0 {
        return ptr::null_mut();
    }
    let Some(layout) = kmalloc_layout(size) else {
        return ptr::null_mut();
    };

    let mut heap = HEAP.lock();
    // SAFETY: non-zero size checked; lock grants exclusive access.
    let raw = match unsafe { heap.malloc(layout) } {
        Ok(nn) => nn.as_ptr(),
        Err(()) => {
            drop(heap);
            klog!("mm::kmalloc: OOM ({} bytes)\n", size);
            return ptr::null_mut();
        }
    };
    drop(heap);

    // Stash the size in the prefix and hand the caller the payload.
    // SAFETY: `raw` is 16-byte aligned and points to `size + 16` bytes
    // of exclusive storage; writing a `usize` to the first word is
    // within bounds and properly aligned.
    unsafe {
        (raw as *mut usize).write(size);
        raw.add(KMALLOC_PREFIX)
    }
}

pub fn kfree(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: `ptr` came from `kmalloc` which returned `raw + 16`, so
    // `ptr - 16` is the original talc allocation and the first word is
    // the size we stored.
    unsafe {
        let raw = ptr.sub(KMALLOC_PREFIX);
        let size = (raw as *const usize).read();
        let Some(layout) = kmalloc_layout(size) else {
            klog!("mm::kfree: corrupt size prefix\n");
            return;
        };
        let Some(nn) = NonNull::new(raw) else { return };
        let mut heap = HEAP.lock();
        heap.free(nn, layout);
    }
}

// ============================================================================
// Heap statistics
// ============================================================================

/// Point-in-time snapshot of the kernel heap. Populated from `talc`'s
/// built-in counters (`counters` feature) — no second pass over the
/// free list is needed.
#[derive(Debug, Clone, Copy)]
pub struct HeapStats {
    /// Bytes currently in flight (sum of live allocation sizes).
    pub allocated_bytes: usize,
    /// Bytes claimed but not allocated (free holes in the heap).
    pub available_bytes: usize,
    /// Total bytes the allocator controls (the heap span claimed
    /// at boot, minus a few bytes of talc bookkeeping).
    pub claimed_bytes: usize,
    /// Number of live allocations.
    pub allocation_count: usize,
    /// Number of free holes (fragmentation indicator).
    pub fragment_count: usize,
    /// Cumulative allocations since boot — useful as an
    /// "allocator hot or cold?" sanity check.
    pub total_allocation_count: u64,
}

/// Snapshot the kernel heap. Cheap: `talc` maintains the counters
/// inline, so this is O(1) plus the spinlock.
pub fn heap_stats() -> HeapStats {
    let heap = HEAP.lock();
    let c = heap.get_counters();
    HeapStats {
        allocated_bytes: c.allocated_bytes,
        available_bytes: c.available_bytes,
        claimed_bytes: c.claimed_bytes,
        allocation_count: c.allocation_count,
        fragment_count: c.fragment_count,
        total_allocation_count: c.total_allocation_count,
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
