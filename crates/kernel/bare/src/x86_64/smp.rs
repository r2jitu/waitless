// kernel/x86_64/smp.rs — Multi-core boot for x86_64.
//
// Uses INIT-SIPI-SIPI to start secondary cores (APs).
// The AP trampoline (boot/x86_64/ap_boot.S) transitions from
// 16-bit real mode to 64-bit long mode.

use super::apic;
use crate::mm;
use crate::serial;
use crate::time;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Per-core stack size: 256 KiB — matches the BSP's `limine_stack`
/// (see `boot/limine_entry.rs`). Limine's default MP stack is only
/// 64 KiB, which the deep TLS-handshake/decrypt path (large RustCrypto
/// scalar-mult temporaries) plus the 12-subsystem `/obs` render
/// overruns on a secondary core — corrupting the stack under load and
/// faulting only on APs (the BSP already has 256 KiB), the "high-load
/// crash" signature. Both AP entry paths switch to a stack of this
/// size before entering the (never-returning) event loop.
const AP_STACK_SIZE: usize = 256 * 1024;

/// Physical address where the AP trampoline is copied.
/// Must be page-aligned and below 1MB. 0x8000 is conventionally safe.
const AP_TRAMPOLINE_ADDR: u64 = 0x8000;

/// Global shutdown flag.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);
static NUM_CORES_ONLINE: AtomicU32 = AtomicU32::new(1);

/// Get current CPU's logical core index.
///
/// Reads from GS:0 which is the `id` field of this core's PerCore struct.
/// Each core sets GS_BASE to point at its PerCore during boot.
/// Cost: one segment-prefixed load (~1 cycle) vs APIC MMIO (~200+ under TCG).
pub fn cpu_id() -> u32 {
    let id: u32;
    unsafe {
        core::arch::asm!(
            "mov {:e}, gs:[0]",
            out(reg) id,
            options(nomem, nostack, preserves_flags),
        );
    }
    id
}

/// Set GS_BASE to point at this core's PerCore struct. Called once per core.
pub fn init_tls(id: u32) {
    unsafe {
        let addr = crate::percpu::get(id) as *const crate::percpu::PerCore as u64;
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0xC0000101u32, // IA32_GS_BASE
            in("eax") addr as u32,
            in("edx") (addr >> 32) as u32,
            options(nomem, nostack),
        );
    }
    // Load this core's per-core TSS so its `ist1` double-fault stack is
    // active (see `gdt`). The BSP (id 0) already `ltr`'d its TSS in
    // `gdt::init`; re-loading it here would fault on a busy TSS, so APs
    // only.
    if id != 0 {
        super::gdt::load_tss(id);
    }
}

/// Number of online cores. Acquire pairs with the AP's `SeqCst` `fetch_add`
/// in `ap_main_x86`, matching the aarch64 SMP code so the BSP's wait-loop
/// is well-defined under the abstract memory model (not just x86 TSO).
pub fn num_cores_online() -> u32 {
    NUM_CORES_ONLINE.load(Ordering::Acquire)
}

/// AP entry point for the Limine MP boot path.
///
/// Called from a short `extern "C" fn(&Cpu) -> !` wrapper in
/// `boot/limine_entry.rs`: Limine has already put the AP in long
/// mode on its own page tables + a 64 KiB stack from Limine's AP
/// pool, and the wrapper extracts the LAPIC ID from the `Cpu` struct
/// before calling us. Keeping the `Cpu` type confined to the boot
/// crate lets `kernel` avoid a build-time dep on the limine crate.
///
/// # Safety
///
/// Must be invoked exactly once per AP, by the Limine MP boot path,
/// with `apic_id` set to that AP's real LAPIC ID. The AP must already
/// be in 64-bit long mode on a valid stack. ACPI topology must have
/// been parsed on the BSP first.
pub unsafe extern "C" fn ap_entry_via_limine(apic_id: u32) -> ! {
    // Enable SSE + AVX on this AP. Limine puts us in long mode but
    // doesn't touch CR4 / XCR0 — those are per-CPU register bits the
    // BSP configures for itself in `boot/limine_entry.rs`'s asm stub,
    // and every other core has to repeat. Without this, the first
    // AVX / YMM / BMI2 instruction the TLS stack runs on an AP
    // (p256 scalar-mult, chacha20 mixing, etc.) raises #UD and
    // halts the core — observed as silent TLS timeouts on GCE
    // n2-highcpu-4 where the TLS handshake happened to land on an
    // AP.
    //
    // Sequence matches `limine_entry_stub` in boot/limine_entry.rs:
    //   - CR4.OSFXSR (9) + CR4.OSXMMEXCPT (10) unconditionally.
    //   - CR4.OSXSAVE (18) + XSETBV only if CPUID reports XSAVE.
    //   - XCR0 masked by CPUID.0Dh:EAX to avoid enabling features
    //     the CPU doesn't actually support.
    unsafe {
        core::arch::asm!(
            // push/pop rbx manually: LLVM reserves rbx as the base
            // pointer in inline asm and rejects it as an operand,
            // but CPUID clobbers ebx. Saving it around each CPUID
            // sidesteps the restriction without needing a separate
            // global_asm stub.
            "mov %cr4, %rax",
            "or  $(1 << 9) | (1 << 10), %rax",
            "mov %rax, %cr4",
            "mov $1, %eax",
            "push %rbx",
            "cpuid",
            "pop %rbx",
            "test $(1 << 26), %ecx",
            "jz 2f",
            "mov %cr4, %rax",
            "or  $(1 << 18), %rax",
            "mov %rax, %cr4",
            "mov $0xD, %eax",
            "xor %ecx, %ecx",
            "push %rbx",
            "cpuid",
            "pop %rbx",
            "and $0x7, %eax",
            "xor %rcx, %rcx",
            "xor %rdx, %rdx",
            "xsetbv",
            "2:",
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            options(att_syntax),
        );

        super::gdt::load_on_ap();
        apic::init_ap();

        let topo = super::acpi::topology();
        let mut logical_id = 0u32;
        for i in 0..topo.cpu_count as usize {
            if topo.apic_ids[i] as u32 == apic_id {
                logical_id = i as u32;
                break;
            }
        }
        init_tls(logical_id);
        super::idt::load_idt_on_ap();

        // AcqRel pairs with the Acquire in `num_cores_online()`; matches
        // the aarch64 sibling. SeqCst would add a redundant fence.
        NUM_CORES_ONLINE.fetch_add(1, Ordering::AcqRel);

        let id = cpu_id();
        let mut buf = [0u8; 24];
        let mut pos = 0;
        for &b in b"[SMP] core " {
            buf[pos] = b;
            pos += 1;
        }
        pos += fmt_u32(&mut buf[pos..], id);
        for &b in b" online\n" {
            buf[pos] = b;
            pos += 1;
        }
        serial::puts(&buf[..pos]);

        // Switch off Limine's 64 KiB MP stack onto a dedicated
        // `AP_STACK_SIZE` (256 KiB) per-core stack — guarded by an
        // unmapped page just below it (see `alloc_guarded_stack`) —
        // before entering the never-returning event loop. The deep
        // TLS-decrypt + `/obs` render path overruns 64 KiB on a
        // secondary core; the guard turns any future over-run into a
        // clean #DF instead of silent corruption. `sti` is deferred to
        // the trampoline so the switch runs interrupts-masked.
        let stack_top = alloc_guarded_stack(id, AP_STACK_SIZE);
        if stack_top != 0 {
            core::arch::asm!(
                "mov rsp, {sp}",
                "call {f}",
                sp = in(reg) stack_top,
                f = sym ap_run_on_stack,
                in("edi") id,
                options(noreturn),
            );
        }
        // Mapping failed (OOM) — run on Limine's (small) stack rather
        // than leaving this core parked.
        core::arch::asm!("sti", options(nomem, nostack));
        crate::eventloop::run(id);
    }
}

/// Enter the event loop on a freshly-switched per-core stack. `extern
/// "C"` so the stack-switch `call` in `ap_entry_via_limine` passes the
/// core id in `edi` per the System V ABI. Enables interrupts (deferred
/// from the switch) before looping.
extern "C" fn ap_run_on_stack(id: u32) -> ! {
    // SAFETY: ring-0; re-enable maskable interrupts now that we're on
    // the dedicated event-loop stack.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
    crate::eventloop::run(id)
}

// ---- Guarded per-core worker stacks ---------------------------------------

/// Dedicated VA region for per-core worker stacks. Each core's stack is
/// mapped here at 4 KiB granularity with an unmapped GUARD PAGE just
/// below it, so a stack overflow faults on the guard (→ #PF, or → #DF on
/// the IST stack once the stack is fully exhausted; see `gdt`/`idt`)
/// instead of silently corrupting neighbouring memory. Canonical, PML4
/// slot 0x180 — distinct from the HHDM (0x100) and higher-half kernel
/// (0x1FF), so the 4 KiB mapper's intermediate tables never collide with
/// the existing mappings.
const STACK_REGION_BASE: u64 = 0xffff_c000_0000_0000;
/// Per-core VA slot; 2 MiB easily holds the guard + `AP_STACK_SIZE` with
/// slack (one PD entry's worth of PTs per core).
const STACK_SLOT_SIZE: u64 = 2 * 1024 * 1024;

/// Serializes worker-stack mapping: the page tables are shared across
/// cores and Limine APs come up concurrently.
static STACK_MAP_LOCK: AtomicBool = AtomicBool::new(false);

/// Allocate `size` bytes of physical stack and map it into this core's
/// slot of the dedicated stacks region with an unmapped guard page
/// below. Returns the 16-byte-aligned stack top to load into RSP, or 0
/// on failure (the caller then falls back to an unguarded stack).
fn alloc_guarded_stack(core_id: u32, size: usize) -> u64 {
    // Keep the slot inside this PML4 entry (512 GiB); absurd ids fall back.
    if (core_id as u64).saturating_mul(STACK_SLOT_SIZE) >= (1u64 << 39) {
        return 0;
    }
    debug_assert!(size % 4096 == 0, "worker stack size must be a page multiple");
    let pages = size / 4096;
    let phys = mm::alloc_pages(pages);
    if phys == 0 {
        return 0;
    }
    // Guard page = slot base; usable stack starts one page above it.
    let slot_base = STACK_REGION_BASE + core_id as u64 * STACK_SLOT_SIZE;
    let stack_lo = slot_base + 4096;

    while STACK_MAP_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // SAFETY: `stack_lo` is in the dedicated, otherwise-unmapped stacks
    // region; the lock serializes edits to the shared page tables.
    let ok = unsafe { crate::mmu::map_pages_4k(stack_lo, phys, pages) };
    STACK_MAP_LOCK.store(false, Ordering::Release);

    if !ok {
        return 0;
    }
    (stack_lo + size as u64) & !0xF
}

/// Boot secondary cores via INIT-SIPI-SIPI (Multiboot2 / PVH path).
///
/// # Safety
///
/// Must run once on the BSP, before any AP starts, only on the
/// Multiboot2 / PVH boot path where low physical memory (including
/// the trampoline page at 0x8000) is identity-mapped. ACPI topology
/// must already be parsed. Overwrites the physical page at
/// `AP_TRAMPOLINE_ADDR`.
pub unsafe fn start_secondary_cores(cpu_count: u32) {
    unsafe {
        if cpu_count <= 1 {
            return;
        }
        let count = cpu_count;
        serial::puts(b"[SMP] Starting secondary cores...\n");

        // Copy AP trampoline to physical 0x8000. Multiboot2 / PVH leave
        // low memory identity-mapped, so we can write there by virtual
        // address directly; this path never runs under Limine (Limine
        // uses its own MP request via ap_entry_via_limine), so no HHDM
        // indirection needed here.
        unsafe extern "C" {
            static ap_trampoline_start: u8;
            static ap_trampoline_end: u8;
        }
        let trampoline_src = &ap_trampoline_start as *const u8;
        let trampoline_size =
            (&ap_trampoline_end as *const u8 as usize) - (trampoline_src as usize);
        let trampoline_dst = AP_TRAMPOLINE_ADDR as *mut u8;

        core::ptr::copy_nonoverlapping(trampoline_src, trampoline_dst, trampoline_size);

        // Set up the GDT at offset 0xF00 in the trampoline page
        let gdt_ptr_addr = (AP_TRAMPOLINE_ADDR + 0xF00) as *mut u8;
        setup_ap_gdt(gdt_ptr_addr);

        // AP inherits BSP's CR3: under Multiboot2 / PVH that PML4 already
        // identity-maps low memory (including the trampoline page at
        // 0x8000) and the kernel's load range, which is exactly what the
        // trampoline's real-mode → long-mode transition needs.
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));

        // Write PML4 address at offset 0xFF0
        let pml4_slot = (AP_TRAMPOLINE_ADDR + 0xFF0) as *mut u32;
        core::ptr::write_volatile(pml4_slot, cr3 as u32);

        let sipi_vector = (AP_TRAMPOLINE_ADDR / 0x1000) as u8;

        // Broadcast INIT to all APs at once and pay the 10 ms post-INIT
        // wait (Intel SDM Vol 3 8.4.4.1) only once instead of per AP.
        // After INIT each AP is in wait-for-SIPI; SIPIs are still sent
        // sequentially because each AP needs its own stack written into
        // the shared trampoline page at offset 0xFF8 before it runs.
        apic::send_init_broadcast();
        time::udelay(10_000);

        let topo = super::acpi::topology();
        for i in 1..count {
            let stack_pages = AP_STACK_SIZE / 4096;
            let stack_base = mm::alloc_pages(stack_pages);
            if stack_base == 0 {
                serial::puts(b"[SMP] Failed to allocate AP stack\n");
                continue;
            }
            let stack_top = stack_base + AP_STACK_SIZE as u64;
            let stack_slot = (AP_TRAMPOLINE_ADDR + 0xFF8) as *mut u64;
            core::ptr::write_volatile(stack_slot, stack_top);

            let target_apic_id = topo.apic_ids[i as usize] as u32;
            let expected = num_cores_online() + 1;

            apic::send_sipi(target_apic_id, sipi_vector);
            time::udelay(200); // 200 µs between SIPIs (per SDM)
            apic::send_sipi(target_apic_id, sipi_vector);

            // Wait up to 100 ms for the AP to come online before starting
            // the next one (the trampoline page at 0x8000 is reused).
            let deadline = time::now_cycles().wrapping_add(100_000 * time::cycles_per_us());
            while num_cores_online() < expected && time::now_cycles() < deadline {
                core::hint::spin_loop();
            }
        }

        // No outer wait or count snapshot. Each AP prints its own
        // `[SMP] core N online` line from `ap_entry_x86`; that's the
        // source of truth. The per-AP wait above is still required
        // (the trampoline page at 0x8000 is shared and must be reused
        // for the next AP). See `aarch64::smp::start_secondary_cores`
        // for the same removal rationale on the ARM side.
        let _ = count;
    }
}

/// IPI wakeup vector (must not conflict with PIC IRQs 32-47 or exceptions 0-31).
pub const IPI_VECTOR: u8 = 0x40;

/// AP entry point — called from the trampoline in 64-bit mode.
#[unsafe(no_mangle)]
extern "C" fn ap_entry_x86(_ctx: u64) -> ! {
    // Load BSP's GDT (AP trampoline GDT has wrong selector layout for IDT).
    super::gdt::load_on_ap();

    // Initialize this AP's APIC
    unsafe {
        apic::init_ap();
    }

    // Set GS_BASE for fast cpu_id() — look up logical core index from APIC ID.
    let apic_id = apic::apic_id();
    let topo = super::acpi::topology();
    let mut logical_id = 0u32;
    for i in 0..topo.cpu_count as usize {
        if topo.apic_ids[i] as u32 == apic_id {
            logical_id = i as u32;
            break;
        }
    }
    init_tls(logical_id);

    // Load the IDT (same one BSP set up) so this AP can handle interrupts.
    super::idt::load_idt_on_ap();

    // Mark online
    // AcqRel pairs with the Acquire in `num_cores_online()`; matches
    // the aarch64 sibling. SeqCst would add a redundant fence.
    NUM_CORES_ONLINE.fetch_add(1, Ordering::AcqRel);

    let id = cpu_id();
    let mut buf = [0u8; 24];
    let mut pos = 0;
    for &b in b"[SMP] core " {
        buf[pos] = b;
        pos += 1;
    }
    pos += fmt_u32(&mut buf[pos..], id);
    for &b in b" online\n" {
        buf[pos] = b;
        pos += 1;
    }
    serial::puts(&buf[..pos]);

    // Enable interrupts so IPI can be delivered.
    unsafe {
        core::arch::asm!("sti", options(nomem, nostack));
    }

    // Enter the unified kernel event loop.
    crate::eventloop::run(id);
}

/// Signal APs to shut down.
pub fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::Relaxed);
    // On x86, APs will wake from HLT on next interrupt and check SHUTDOWN.
    // Send IPI to all APs to wake them.
    // For simplicity, broadcast NMI (vector 2) — they'll check SHUTDOWN.
}

/// Set up a minimal GDT for the AP trampoline at the given address.
/// Format: 2 bytes limit + 4 bytes base (32-bit GDT pointer for lgdt in 16/32-bit mode)
/// followed by GDT entries.
unsafe fn setup_ap_gdt(addr: *mut u8) {
    unsafe {
        // GDT entries start at addr + 6 (after the 6-byte GDT pointer)
        let gdt_base = addr.add(6);

        // Entry 0 (0x00): null descriptor
        core::ptr::write_bytes(gdt_base, 0, 8);

        // Entry 1 (0x08): 32-bit code segment (for real→protected mode)
        let e1 = gdt_base.add(8) as *mut u64;
        // Limit=0xFFFFF, Base=0, Access=0x9A, Flags=0xC0 (G=1,D=1,L=0)
        core::ptr::write_volatile(e1, 0x00CF9A000000FFFFu64);

        // Entry 2 (0x10): 32-bit data segment
        let e2 = gdt_base.add(16) as *mut u64;
        // Limit=0xFFFFF, Base=0, Access=0x92, Flags=0xC0 (G=1,D=1)
        core::ptr::write_volatile(e2, 0x00CF92000000FFFFu64);

        // Entry 3 (0x18): 64-bit code segment (for protected→long mode)
        let e3 = gdt_base.add(24) as *mut u64;
        // Limit=0, Base=0, Access=0x9A, Flags=0xA0 (L=1,D=0)
        core::ptr::write_volatile(e3, 0x00209A0000000000u64);

        // GDT pointer: limit (4 entries × 8 - 1 = 31), base = physical addr of GDT
        let ptr = addr as *mut u16;
        core::ptr::write_volatile(ptr, 31); // limit
        let base_ptr = addr.add(2) as *mut u32;
        core::ptr::write_volatile(base_ptr, gdt_base as u32);
    }
}

fn fmt_u32(buf: &mut [u8], mut val: u32) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut len = 0;
    while val > 0 {
        tmp[len] = b'0' + (val % 10) as u8;
        val /= 10;
        len += 1;
    }
    for i in 0..len {
        buf[i] = tmp[len - 1 - i];
    }
    len
}
