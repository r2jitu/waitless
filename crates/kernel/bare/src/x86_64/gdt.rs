// kernel/x86_64/gdt.rs -- Global Descriptor Table implementation
//
// Sets up the flat-model GDT for x86_64 long mode:
//   Entry 0:        Null descriptor
//   Entry 1:        64-bit kernel code segment (selector 0x08)
//   Entry 2:        Kernel data segment (selector 0x10)
//   Entry 3 + 2*i:  Per-core TSS descriptor (16 bytes) for core `i`,
//                   selector `TSS_SELECTOR + i*0x10`.
//
// After loading the GDTR, we reload CS via a far return and set all
// data segment registers to the kernel data selector.
//
// Per-core TSS + #DF IST stack (stack-overflow hardening)
// -------------------------------------------------------
// Each core gets its own TSS whose `ist1` points at a dedicated
// double-fault stack. The #DF IDT gate (`idt::init`) selects `ist=1`,
// so when a worker stack overflows into its guard page the resulting
// fault — which can't push its frame on the exhausted stack — is taken
// on this fresh IST stack instead of triple-faulting into a silent
// reboot. One TSS per core is required: `ltr` marks a TSS descriptor
// *busy*, so two cores can't load the same one. The BSP loads its TSS
// in `init`; APs call `load_tss` after `load_on_ap`.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::mem;

// Segment selectors
pub const KERNEL_CODE_SELECTOR: u16 = 0x08;
pub const KERNEL_DATA_SELECTOR: u16 = 0x10;
/// TSS selector for core 0. Core `i`'s selector is `TSS_SELECTOR +
/// i*0x10` — each 64-bit TSS descriptor is 16 bytes = two GDT slots.
pub const TSS_SELECTOR: u16 = 0x18;

/// Cores we set up a per-core TSS + #DF IST stack for. A core past this
/// index gets no IST — a #DF there triple-faults as it did before (no
/// regression), but every realistic deployment is far under this.
const MAX_CPUS: usize = 16;

/// Per-core double-fault IST stack size. The #DF handler only runs the
/// unhandled-exception dump (registers + a short backtrace), so this is
/// generous headroom.
const DF_IST_SIZE: usize = 16 * 1024;

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
#[derive(Copy, Clone)]
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

const ZERO_TSS: Tss = Tss {
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
};

/// 3 fixed entries (null/code/data) + a 16-byte (two-slot) TSS
/// descriptor per core.
const GDT_ENTRIES: usize = 3 + 2 * MAX_CPUS;

// ---------------------------------------------------------------------------
// Static storage (bare-metal, single-threaded)
// ---------------------------------------------------------------------------
//
// `init()` writes the shared GDT + every per-core TSS on the BSP during
// boot, before any AP is started and before any IDT/interrupt is live.
// After that the GDT is read-only; `load_on_ap()`/`load_tss()` only read
// it. `TSSES[i].rsp0` is rewritten by the BSP-only `set_kernel_stack`.
// `lgdt`/`ltr` take raw pointers and the tables must live where the CPU
// can physically see them, so plain `UnsafeCell` statics are the right
// primitive — no heap indirection.

/// Aggregate of the shared GDT state.
struct GdtState {
    entries: [GdtEntry; GDT_ENTRIES],
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
            }; GDT_ENTRIES],
            gdtr: DescriptorTablePtr { limit: 0, base: 0 },
        }
    }
}

struct GdtCell(UnsafeCell<GdtState>);
// SAFETY: all mutation is single-threaded by contract (see module comment).
unsafe impl Sync for GdtCell {}

static GDT: GdtCell = GdtCell(UnsafeCell::new(GdtState::new()));

/// Per-core TSSes. The GDT's per-core TSS descriptors point here.
struct TssCell(UnsafeCell<[Tss; MAX_CPUS]>);
// SAFETY: each core touches only its own TSS, set up before APs run.
unsafe impl Sync for TssCell {}
static TSSES: TssCell = TssCell(UnsafeCell::new([const { ZERO_TSS }; MAX_CPUS]));

/// Per-core double-fault IST stacks. The CPU loads `rsp` from
/// `TSS.ist1` before pushing the #DF frame, so the handler runs on a
/// fresh stack even when the faulting core's own stack is exhausted.
#[repr(C, align(16))]
struct DfIstStack([u8; DF_IST_SIZE]);
struct DfIstCell(UnsafeCell<[DfIstStack; MAX_CPUS]>);
// SAFETY: written only by hardware (the CPU) on a #DF; each core uses
// only its own slot.
unsafe impl Sync for DfIstCell {}
static DF_IST: DfIstCell =
    DfIstCell(UnsafeCell::new([const { DfIstStack([0u8; DF_IST_SIZE]) }; MAX_CPUS]));

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

/// Initialize the GDT with kernel code/data segments and a per-core TSS
/// (each carrying a #DF IST stack). Loads the GDTR, reloads all segment
/// registers, and loads the BSP's TSS.
pub fn init() {
    unsafe {
        // Per-core TSS descriptors + each TSS's #DF IST stack (`ist1`).
        // SAFETY: BSP-only during boot; no AP/interrupt is live yet.
        let tsses = &mut *TSSES.0.get();
        let df_ist = &*DF_IST.0.get();

        // Entry 0: Null descriptor
        set_entry(0, 0, 0, 0, 0);
        // Entry 1: Kernel code (selector 0x08). Access 0x9A; flags 0xA0 (L=1).
        set_entry(1, 0, 0xFFFFF, 0x9A, 0xA0);
        // Entry 2: Kernel data (selector 0x10). Access 0x92; flags 0xC0.
        set_entry(2, 0, 0xFFFFF, 0x92, 0xC0);

        for i in 0..MAX_CPUS {
            tsses[i] = ZERO_TSS;
            tsses[i].iopb_offset = mem::size_of::<Tss>() as u16;
            // Stack grows down, so ist1 points at the TOP of the slot.
            tsses[i].ist1 = (&df_ist[i] as *const DfIstStack as u64) + DF_IST_SIZE as u64;
            let tss_base = &raw const tsses[i] as u64;
            set_tss_entry(3 + 2 * i, tss_base, (mem::size_of::<Tss>() - 1) as u32);
        }

        // Load the GDTR. Bind `gdt` only now (after the `set_*` helpers,
        // which each take their own `&mut`) to avoid overlapping borrows.
        let gdt = &mut *GDT.0.get();
        gdt.gdtr.limit = (mem::size_of::<[GdtEntry; GDT_ENTRIES]>() - 1) as u16;
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

        // Load the BSP's Task Register (core 0).
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

/// Load this core's TSS so its `ist1` #DF stack becomes active. Call
/// once per AP after `load_on_ap`; the BSP loads its TSS in `init`.
/// Cores at or past `MAX_CPUS` keep no TSS (a #DF there is unguarded,
/// as it was before this change).
pub fn load_tss(core_id: u32) {
    let i = core_id as usize;
    if i >= MAX_CPUS {
        return;
    }
    let sel = TSS_SELECTOR + (i as u16) * 0x10;
    // SAFETY: each core loads its own (per-core) TSS descriptor exactly
    // once; descriptors are distinct so `ltr` never hits a busy TSS.
    unsafe {
        asm!("ltr {:x}", in(reg) sel, options(nomem, nostack));
    }
}

/// Set the kernel stack pointer in the BSP's TSS (`rsp0`). Ring-0-only
/// kernel, so this is effectively unused, but kept for the context-
/// switch contract.
pub fn set_kernel_stack(stack: u64) {
    // SAFETY: BSP-only; same contract as `init()`.
    unsafe {
        (*TSSES.0.get())[0].rsp0 = stack;
    }
}
