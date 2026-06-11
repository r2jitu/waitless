// Memory management: single talc-backed allocator.
//
// All dynamic memory comes from one `talc` (segregated-free-list)
// heap behind a `Spinlock`. At boot, every `MEM_AVAILABLE` region
// from the boot memory map is claimed into the heap, with the
// kernel image's range punched out so we don't hand the loader's
// own pages to allocators.
//
// `alloc_frame` and `alloc_pages` (used by drivers for DMA buffers
// + virtio rings, and by the SMP layer for AP stacks) are thin
// page-aligned wrappers over the heap — they request a
// `Layout::from_size_align(N × PAGE_SIZE, PAGE_SIZE)`, then return
// the corresponding physical address via `virt_to_phys`. They
// never free; their consumers are once-at-boot allocations that
// live for the program's lifetime.
//
// Why one allocator instead of a separate page allocator:
//   * Drivers don't actually need a different allocator — they
//     need page-aligned, DMA-mappable memory, which is exactly what
//     `talc` gives us with a page-aligned `Layout`.
//   * No fixed `FRAME_RESERVE` constant and no risk of running out
//     of "page pool" while heap has 100 MB free (or vice versa).
//   * Stats (`heap_stats`) cover everything in one place.
//
// Sizes scale with the VM: a 128 MB guest gets a ~125 MB heap, a
// 4 GB GCE instance gets ~3.99 GB.

use core::alloc::Layout;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "none")]
use core::alloc::GlobalAlloc;

use talc::{ErrOnOom, Span, Talc};

// ============================================================================
// Dependencies
// ============================================================================

use crate::once::InitOnce;
use crate::serial;
use obs::{Counter, LastEvent, ObsRecord};
use sync::Spinlock;
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

// ============================================================================
// Memory-map snapshot
// ============================================================================
//
// Total RAM (sum of MEM_AVAILABLE region lengths) and the highest
// observed physical address. Captured once at boot, exposed via
// `total_memory` for `BootInfo` publish + boot logs. Free memory
// is read directly from talc's counters in `free_memory`, so we
// don't need to track allocations here.

static TOTAL_RAM: AtomicU64 = AtomicU64::new(0);
static MAX_PHYS_ADDR: AtomicU64 = AtomicU64::new(0);

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

/// Claim every `MEM_AVAILABLE` region from the boot memory map
/// into the talc heap, splitting around the kernel image so we
/// don't hand the loader's pages out as allocations. Tracks total
/// RAM and the highest physical address for `total_memory`
/// and the boot log.
fn init_heap(info: &BootInfo, kern_end_phys: u64) {
    let kern_start = info.kernel_phys_base;
    let kern_end = kern_end_phys;
    let mut total_ram: u64 = 0;
    let mut max_phys: u64 = 0;
    let mut total_claimed: u64 = 0;

    let mut heap = HEAP.lock();
    for i in 0..info.memory_map_count as usize {
        let r = &info.memory_map[i];
        if r.region_type != MEM_AVAILABLE {
            continue;
        }
        // The x86_64 multiboot/PVH boot stub identity-maps only
        // [0, 4 GiB). QEMU on q35 with `-m > 3 GiB` puts the
        // overflow above 4 GiB (since the 3-4 GiB hole is PCI
        // MMIO), and so does GCE. On those identity-mapped boots
        // (`hhdm_offset == 0`), claiming a region at or above
        // 4 GiB would fault talc on the first write through the
        // unmapped address — skip them, capping the heap at
        // ~3 GiB. Limine sets a nonzero `hhdm_offset` and its
        // HHDM maps every usable region, so the Limine/ISO path
        // (the GCE deploy) claims the full RAM: a c3-highcpu-8
        // gets a ~15.9 GiB heap, not 3 GiB.
        if info.hhdm_offset == 0 && r.base >= 0x1_0000_0000 {
            continue;
        }
        total_ram += r.length;
        let region_end = r.base + r.length;
        if region_end > max_phys {
            max_phys = region_end;
        }

        let rstart = align_up_page(r.base);
        let rend = region_end & !(PAGE_SIZE - 1);
        if rend <= rstart {
            continue;
        }

        // Punch the kernel image's range out of the claim. Three
        // cases: kernel is entirely outside this region (claim it
        // whole), kernel splits the region (claim the two halves
        // separately), or kernel covers the whole region (skip).
        let kern_overlaps = kern_start < rend && kern_end > rstart;
        if !kern_overlaps {
            total_claimed += claim_phys(&mut heap, info.hhdm_offset, rstart, rend - rstart);
            continue;
        }
        if rstart < kern_start {
            let lo = rstart;
            let hi = kern_start & !(PAGE_SIZE - 1);
            if hi > lo {
                total_claimed += claim_phys(&mut heap, info.hhdm_offset, lo, hi - lo);
            }
        }
        let after_kern = align_up_page(kern_end);
        if after_kern < rend {
            total_claimed += claim_phys(&mut heap, info.hhdm_offset, after_kern, rend - after_kern);
        }
    }
    drop(heap);

    TOTAL_RAM.store(total_ram, Ordering::Release);
    MAX_PHYS_ADDR.store(max_phys, Ordering::Release);

    // No internal log lines — the entry-point banner prints a single
    // `Heap: free / total MB` line after `mm::init` returns. Each
    // serial line is ~1 ms on HVF (per-byte vmexit), so the previous
    // 2-line "Physical memory" + "Heap (talc, claimed across …)"
    // dump cost ~2 ms per boot for cosmetics.
    let _ = (total_ram, max_phys, total_claimed);
}

/// Hand `[phys, phys+size)` to talc as a heap span. Returns the
/// number of bytes actually claimed (0 on failure). The span is
/// HHDM-translated to the virtual address talc expects.
fn claim_phys(heap: &mut Talc<ErrOnOom>, hhdm: u64, phys: u64, size: u64) -> u64 {
    let virt = (hhdm + phys) as *mut u8;
    // SAFETY: `[phys, phys+size)` is in a `MEM_AVAILABLE` region
    // and disjoint from the kernel image, the only data the
    // bootloader handed us with active references. The HHDM map
    // makes `virt..virt+size` a valid, kernel-owned address range.
    let span = Span::from_base_size(virt, size as usize);
    unsafe {
        if heap.claim(span).is_ok() {
            size
        } else {
            klog!(
                "  Heap: talc::claim failed at {:#x} ({} bytes)\n",
                phys,
                size
            );
            0
        }
    }
}

// `info` is caller-validated (boot path passes a live BootInfo); marking
// the fn `unsafe` would ripple into the `crates/boot` caller.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
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
    init_heap(info, kern_end_phys);
}

/// Allocate one page-aligned 4 KB page from the heap. Returns the
/// physical address; the caller can recover the virtual via
/// `phys_to_virt` (or just use the returned phys, since the HHDM
/// + identity-mapped boot paths both make `phys = virt - offset`).
///
/// Used by NIC drivers for DMA-mapped virtio queue rings — the
/// device wants a physical address, talc serves the page-aligned
/// virtual chunk, `virt_to_phys` does the rest.
///
/// Allocations from this path are never freed in the current
/// codebase (boot-time DMA buffers and AP stacks live for the
/// program's lifetime), so there's no matching `free_frame`.
pub fn alloc_frame() -> u64 {
    alloc_pages(1)
}

/// Allocate `count` contiguous page-aligned 4 KB pages from the
/// heap. Returns physical address, or 0 on failure.
pub fn alloc_pages(count: usize) -> u64 {
    if count == 0 {
        return 0;
    }
    let layout = match Layout::from_size_align(count * PAGE_SIZE as usize, PAGE_SIZE as usize) {
        Ok(l) => l,
        Err(_) => return 0,
    };
    // SAFETY: `layout` has non-zero size and a valid alignment;
    // the GlobalAlloc contract is satisfied. talc returns a
    // pointer into the kernel-owned HHDM region.
    let virt = unsafe { core::alloc::GlobalAlloc::alloc(&GLOBAL_ALLOCATOR, layout) };
    if virt.is_null() {
        klog!("mm::alloc_pages: heap exhausted ({} pages)\n", count);
        return 0;
    }
    virt_to_phys(virt)
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
                record_oom(layout.size(), layout.align());
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
            record_oom(layout.size(), layout.align());
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

/// Free a pointer previously returned by `kmalloc`.
///
/// # Safety
///
/// `ptr` must be null, or a pointer returned by an earlier `kmalloc`
/// call that has not already been freed. `kfree` reads the 16-byte
/// size prefix `kmalloc` stashed just before `ptr` to reconstruct the
/// `talc` layout.
pub unsafe fn kfree(ptr: *mut u8) {
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

pub fn total_memory() -> usize {
    TOTAL_RAM.load(Ordering::Acquire) as usize
}

// ── Observability: heap OOM (the observability doctrine) ────────────
//
// `docs/observability.md` applied to the kernel. The `diag` ring
// already captures panics + unhandled CPU exceptions (the kernel's
// "last fatal fault"); the gap the doctrine closes is the one
// *non-fatal* kernel anomaly worth counting — an allocation that
// failed. An allocator returning null is a counted-nowhere event
// otherwise; the caller handles the null and carries on, so it can
// recur. `write_obs_json` is the kernel's `/obs` block.

/// Heap allocations that failed — `talc` had no block to satisfy
/// the request, so the allocator returned null. Bumped by both the
/// `GlobalAlloc::alloc` path (`Box` / `Vec` / …) and the legacy
/// `kmalloc` path (virtio-net DMA buffers). Genuinely unexpected on
/// a healthy system; sustained growth means the heap is undersized
/// or something is leaking.
pub static HEAP_OOM: Counter = Counter::new();

/// Most recent failed allocation — the size / alignment `talc`
/// could not satisfy.
pub static LAST_OOM: LastEvent<OomRecord> = LastEvent::new();

/// Snapshot payload for `LAST_OOM`.
#[derive(Clone, Copy)]
pub struct OomRecord {
    pub size: usize,
    pub align: usize,
}

impl ObsRecord for OomRecord {
    fn write_fields(&self, w: &mut dyn core::fmt::Write) -> core::fmt::Result {
        write!(w, "\"size\":{},\"align\":{}", self.size, self.align)
    }
}

/// Record a failed allocation: bump `HEAP_OOM` and snapshot the
/// request into `LAST_OOM`.
fn record_oom(size: usize, align: usize) {
    HEAP_OOM.bump();
    LAST_OOM.record(OomRecord { size, align });
}

/// Render the kernel observability block as JSON — heap statistics
/// plus the OOM counter and `LAST_OOM` snapshot. This is the
/// kernel's `/obs` block; `waitless_backend::kernel_obs_json`
/// forwards it (the native backend has no kernel heap and stubs
/// `{}`).
pub fn write_obs_json(w: &mut dyn core::fmt::Write) -> core::fmt::Result {
    let s = heap_stats();
    write!(
        w,
        "{{\"heap_allocated_bytes\":{},\"heap_available_bytes\":{},\
         \"heap_claimed_bytes\":{},\"heap_allocation_count\":{},\
         \"heap_fragment_count\":{},\"heap_total_allocation_count\":{},\
         \"heap_oom\":{},",
        s.allocated_bytes,
        s.available_bytes,
        s.claimed_bytes,
        s.allocation_count,
        s.fragment_count,
        s.total_allocation_count,
        HEAP_OOM.get(),
    )?;
    // RNG entropy-source health (NIST SP 800-90B) from the cold-boot
    // seed. `rng_seeded` is false until the first `fill_bytes`; once
    // seeded, `rng_min_entropy_mbits` is the most-common-value estimate
    // in milli-bits/symbol and the two `*_pass` flags are the RCT/APT
    // startup tests. A low estimate or a failed test on a real deploy
    // flags a degraded jitter source (e.g. a pathological hypervisor TSC).
    let h = crate::rng::seed_health();
    write!(
        w,
        "\"rng_seeded\":{},\"rng_rct_pass\":{},\"rng_apt_pass\":{},\
         \"rng_min_entropy_mbits\":{},\"rng_jitter_samples\":{},",
        h.is_some(),
        h.map(|r| r.rct_pass).unwrap_or(false),
        h.map(|r| r.apt_pass).unwrap_or(false),
        h.map(|r| r.min_entropy_mbits).unwrap_or(0),
        h.map(|r| r.samples).unwrap_or(0),
    )?;
    // Wall-clock (Unix-epoch seconds) read from the platform RTC at
    // boot, 0 = unavailable (e.g. aarch64 where we don't map the RTC).
    write!(
        w,
        "\"wall_unix_secs\":{},",
        kernel_core::clock::wall_unix_secs(),
    )?;
    LAST_OOM.write_json(w, "last_oom")?;
    w.write_str("}")
}

pub fn free_memory() -> usize {
    heap_stats().available_bytes
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
