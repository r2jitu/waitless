// kernel/x86_64/gdt.rs -- Global Descriptor Table implementation
//
// Sets up the flat-model GDT for x86_64 long mode:
//   Entry 0: Null descriptor
//   Entry 1: 64-bit kernel code segment (selector 0x08)
//   Entry 2: Kernel data segment (selector 0x10)
//   Entry 3-4: TSS descriptor (16 bytes, selector 0x18)
//
// After loading the GDTR, we reload CS via a far return and set all
// data segment registers to the kernel data selector.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::mem;

// Segment selectors
pub const KERNEL_CODE_SELECTOR: u16 = 0x08;
pub const KERNEL_DATA_SELECTOR: u16 = 0x10;
pub const TSS_SELECTOR: u16 = 0x18;

/// 8-byte GDT entry (standard segment descriptor format).
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct GdtEntry {
    limit_low: u16,
    base_low: u16,
    base_middle: u8,
    access: u8,
    granularity: u8,
    base_high: u8,
}

/// GDTR/IDTR layout: 2-byte limit followed by 8-byte base address.
#[repr(C, packed)]
struct DescriptorTablePtr {
    limit: u16,
    base: u64,
}

/// Task State Segment: 104 bytes.
/// Used in long mode primarily for RSP0 (kernel stack for ring transitions)
/// and IST entries (interrupt stack table).
#[repr(C, packed)]
struct Tss {
    reserved0: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    reserved1: u64,
    ist1: u64,
    ist2: u64,
    ist3: u64,
    ist4: u64,
    ist5: u64,
    ist6: u64,
    ist7: u64,
    reserved2: u64,
    reserved3: u16,
    iopb_offset: u16,
}

// ---------------------------------------------------------------------------
// Static storage (bare-metal, single-threaded)
// ---------------------------------------------------------------------------
//
// The GDT state (entries, TSS, GDTR) lives in one `UnsafeCell<GdtState>`
// behind a `GdtSlot(unsafe impl Sync)` wrapper. Single-owner discipline:
// `init()` writes on the BSP during boot, *before* any AP has been
// started via `kernel::x86_64::smp::boot_aps` and *before* any
// interrupt handler runs (the IDT isn't loaded yet either). After that
// point the state is read-only — `load_on_ap()` only reads the
// BSP-initialised GDTR, never writes. `set_kernel_stack` rewrites
// `TSS.rsp0` from the BSP-only context-switch path.
//
// We can't use `InitOnce<Box<_>>` because `lgdt` takes a raw pointer
// and the GDT entries have to live in memory that the CPU can
// physically see during the `retfq` segment reload — any heap
// indirection would unwrap to the same address anyway. UnsafeCell is
// the right primitive: plain static storage, interior mutability, no
// overhead.

/// Aggregate of every persistently-mutated piece of GDT state.
struct GdtState {
    /// 5 entries: null + code + data + TSS low (8 bytes) + TSS high (8 bytes).
    entries: [GdtEntry; 5],
    tss: Tss,
    gdtr: DescriptorTablePtr,
}

impl GdtState {
    const fn new() -> Self {
        Self {
            entries: [GdtEntry {
                limit_low: 0,
                base_low: 0,
                base_middle: 0,
                access: 0,
                granularity: 0,
                base_high: 0,
            }; 5],
            tss: Tss {
                reserved0: 0,
                rsp0: 0,
                rsp1: 0,
                rsp2: 0,
                reserved1: 0,
                ist1: 0,
                ist2: 0,
                ist3: 0,
                ist4: 0,
                ist5: 0,
                ist6: 0,
                ist7: 0,
                reserved2: 0,
                reserved3: 0,
                iopb_offset: 0,
            },
            gdtr: DescriptorTablePtr { limit: 0, base: 0 },
        }
    }
}

struct GdtSlot(UnsafeCell<GdtState>);
// SAFETY: all mutation is single-threaded by contract (see module comment).
unsafe impl Sync for GdtSlot {}

static GDT: GdtSlot = GdtSlot(UnsafeCell::new(GdtState::new()));

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Encode a standard 8-byte GDT entry.
fn set_entry(index: usize, base: u32, limit: u32, access: u8, flags: u8) {
    // SAFETY: BSP-only during `init()` — see module-level comment.
    let gdt = unsafe { &mut *GDT.0.get() };
    let entry = &mut gdt.entries[index];
    entry.limit_low = (limit & 0xFFFF) as u16;
    entry.base_low = (base & 0xFFFF) as u16;
    entry.base_middle = ((base >> 16) & 0xFF) as u8;
    entry.access = access;
    entry.granularity = (flags & 0xF0) | (((limit >> 16) & 0x0F) as u8);
    entry.base_high = ((base >> 24) & 0xFF) as u8;
}

/// Set up the 16-byte TSS descriptor at GDT index `index` (and `index+1`).
/// A system segment descriptor in long mode is 16 bytes.
fn set_tss_entry(index: usize, base: u64, limit: u32) {
    // SAFETY: BSP-only during `init()` — see module-level comment.
    let gdt = unsafe { &mut *GDT.0.get() };

    // First 8 bytes (standard descriptor format)
    let entry = &mut gdt.entries[index];
    entry.limit_low = (limit & 0xFFFF) as u16;
    entry.base_low = (base & 0xFFFF) as u16;
    entry.base_middle = ((base >> 16) & 0xFF) as u8;
    // Access: Present=1, DPL=0, Type=0x9 (64-bit TSS available)
    entry.access = 0x89;
    entry.granularity = ((limit >> 16) & 0x0F) as u8;
    entry.base_high = ((base >> 24) & 0xFF) as u8;

    // Second 8 bytes: upper 32 bits of base address + reserved
    let upper = &mut gdt.entries[index + 1];
    let base_upper = ((base >> 32) & 0xFFFFFFFF) as u32;
    // Write base_upper into the first 4 bytes of the slot
    upper.limit_low = (base_upper & 0xFFFF) as u16;
    upper.base_low = ((base_upper >> 16) & 0xFFFF) as u16;
    // Remaining 4 bytes are reserved (zero)
    upper.base_middle = 0;
    upper.access = 0;
    upper.granularity = 0;
    upper.base_high = 0;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize the GDT with kernel code/data segments and TSS.
/// Loads the GDTR, reloads all segment registers, and loads the TSS.
pub fn init() {
    unsafe {
        // SAFETY: BSP-only during boot — see module-level comment.
        let gdt = &mut *GDT.0.get();

        // Zero out the TSS
        core::ptr::write_bytes(&raw mut gdt.tss as *mut u8, 0, mem::size_of::<Tss>());

        // Set the I/O permission bitmap offset past the end of the TSS
        gdt.tss.iopb_offset = mem::size_of::<Tss>() as u16;

        // Entry 0: Null descriptor
        set_entry(0, 0, 0, 0, 0);

        // Entry 1: Kernel code segment (selector 0x08)
        // Access: Present=1, DPL=0, S=1, Exec=1, DC=0, RW=1, Accessed=0 = 0x9A
        // Flags: G=0, L=1 (long mode), D=0, AVL=0 => upper nibble = 0xA0
        set_entry(1, 0, 0xFFFFF, 0x9A, 0xA0);

        // Entry 2: Kernel data segment (selector 0x10)
        // Access: Present=1, DPL=0, S=1, Exec=0, DC=0, RW=1, Accessed=0 = 0x92
        // Flags: G=1, D=1, L=0, AVL=0 => upper nibble = 0xC0
        set_entry(2, 0, 0xFFFFF, 0x92, 0xC0);

        // Entry 3-4: TSS descriptor (16 bytes, selector 0x18)
        let tss_base = &raw const gdt.tss as u64;
        set_tss_entry(3, tss_base, (mem::size_of::<Tss>() - 1) as u32);

        // Load the GDTR
        gdt.gdtr.limit = (mem::size_of::<[GdtEntry; 5]>() - 1) as u16;
        gdt.gdtr.base = &raw const gdt.entries as *const _ as u64;

        let gdtr_ptr = &raw const gdt.gdtr;
        asm!("lgdt [{}]", in(reg) gdtr_ptr, options(nostack));

        // Reload CS via far return, then set data segment registers
        asm!(
            // Push new code selector and return address for lretq
            "push {cs}",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            // Reload data segment registers
            "mov ax, {ds:x}",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "xor ax, ax",
            "mov fs, ax",
            "mov gs, ax",
            cs = const KERNEL_CODE_SELECTOR as u64,
            ds = in(reg) KERNEL_DATA_SELECTOR,
            out("rax") _,
        );

        // Load the Task Register
        asm!("ltr {:x}", in(reg) TSS_SELECTOR, options(nomem, nostack));
    }
}

/// Load the BSP's GDT on an AP. Reloads segment registers for the new GDT layout.
pub fn load_on_ap() {
    unsafe {
        // SAFETY: GDT state is immutable after BSP init — APs only read it.
        let gdtr_ptr = &raw const (*GDT.0.get()).gdtr;
        asm!("lgdt [{}]", in(reg) gdtr_ptr, options(nostack));

        // Reload CS via far return, then reload data segments.
        asm!(
            "push {cs}",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            "mov ax, {ds:x}",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "xor ax, ax",
            "mov fs, ax",
            "mov gs, ax",
            cs = const KERNEL_CODE_SELECTOR as u64,
            ds = in(reg) KERNEL_DATA_SELECTOR,
            out("rax") _,
        );
    }
}

/// Set the kernel stack pointer in the TSS.
/// When an interrupt occurs in ring 3, the CPU switches RSP to this value.
pub fn set_kernel_stack(stack: u64) {
    // SAFETY: BSP-only; same contract as `init()`.
    unsafe { (*GDT.0.get()).tss.rsp0 = stack; }
}
