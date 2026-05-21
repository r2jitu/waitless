// kernel/limine_entry.rs — Limine boot protocol entry point (Rust)
//
// When the kernel is loaded by the Limine bootloader, it calls limine_entry()
// instead of the normal boot.S _start. Limine has already set up:
//   - 64-bit mode (x86) or EL1 (aarch64), MMU on, paging enabled
//   - BSS zeroed, valid stack
//   - Identity mapping of first 4 GiB + HHDM (under base revision 0)
//
// All Limine request/response structs and the .limine_requests link sections
// come from the upstream `limine` crate (version 0.5.0). The crate provides
// the request types with the right `link_section` and `used` attributes baked
// into them, plus PHDR-friendly start/end markers — replacing ~250 lines of
// hand-written bindings that were prone to layout bugs.

#![no_std]

// The kernel's sole `#[panic_handler]` lives in `entry` (boot/entry.rs)
// and serves every boot path — multiboot, Limine, HVF. Now that the
// boot crates are rlibs sharing one crate graph, a second handler here
// would collide on the `panic_impl` lang item.

use kernel_bare::types::{
    BootInfo, MAX_MEMORY_REGIONS, MEM_AVAILABLE, MEM_RESERVED, MemoryRegion, Protocol,
};

use limine::BaseRevision;
use limine::memory_map::EntryType;
use limine::request::{
    ExecutableAddressRequest, HhdmRequest, MemoryMapRequest, RequestsEndMarker, RequestsStartMarker,
};

#[cfg(target_arch = "aarch64")]
use limine::request::DeviceTreeBlobRequest;
#[cfg(target_arch = "x86_64")]
use limine::request::{ExecutableCmdlineRequest, MpRequest, RsdpRequest};

// x86_64 SSE + AVX enable stub — Limine drops us in 64-bit mode
// with MMU + paging but does NOT enable the OS-level bits the
// compiler needs before executing SIMD instructions. Matches
// the BSP sequence in `boot/x86_64/boot.S`:
//
//   - CR4.OSFXSR (9) + CR4.OSXMMEXCPT (10) unconditionally so
//     any XMM instruction (the common SSE2 path) works.
//   - CR4.OSXSAVE (18) + XSETBV only if CPUID reports XSAVE, so
//     the kernel still boots on pre-AVX CPUs that lack XSAVE.
//   - XCR0 is masked with CPUID.0Dh:EAX so we only enable bits
//     (x87|SSE|AVX) that the CPU actually supports.
//
// Without this, p256 / aes-gcm / etc. compiled with the
// MODULE.bazel `+avx,+avx2` annotation crash with `#UD` on
// the first YMM instruction — manifests as a silent guest hang
// during TLS config init.
//
// Also switches to our own 256 KiB stack before calling the Rust
// entry. Limine's default stack is only 64 KiB, which
// Server::new_boxed (+ TlsServerConfig::from_dev_cert + the
// RustCrypto scalar-mult temporaries) overruns, triple-faulting
// the guest the moment main() starts. Matches boot/x86_64/boot.S
// where the multiboot path uses a 256 KiB stack_top.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".section .bss",
    ".align 16",
    ".global limine_stack_bottom",
    "limine_stack_bottom:",
    "    .space 262144", // 256 KiB
    ".global limine_stack_top",
    "limine_stack_top:",
    ".section .text",
    ".code64",
    ".global limine_entry_stub",
    "limine_entry_stub:",
    "    lea limine_stack_top(%rip), %rsp",
    "    mov %cr4, %rax",
    "    or  $(1 << 9) | (1 << 10), %rax",
    "    mov %rax, %cr4",
    "    mov $1, %eax",
    "    cpuid",
    "    test $(1 << 26), %ecx", // CPUID.01h:ECX.XSAVE
    "    jz 2f",
    "    mov %cr4, %rax",
    "    or  $(1 << 18), %rax", // CR4.OSXSAVE
    "    mov %rax, %cr4",
    "    mov $0xD, %eax",
    "    xor %ecx, %ecx",
    "    cpuid",
    "    and $0x7, %eax", // x87|SSE|AVX AND supported
    "    xor %rcx, %rcx",
    "    xor %rdx, %rdx",
    "    xsetbv",
    "2:",
    "    xor %rbp, %rbp",
    "    and $-16, %rsp",
    "    call limine_entry",
    "3: cli",
    "    hlt",
    "    jmp 3b",
    options(att_syntax),
);

#[cfg(target_arch = "aarch64")]
use kernel_bare::aarch64::{fdt, mmu};

// ============================================================================
// Limine request statics — placed in .limine_requests* by the crate.
// ============================================================================
//
// Base revision 0: provides an unconditional 4 GiB identity map AND HHDM
// coverage of every memory-map region, so the kernel can read MMIO (Local
// APIC, virtio-pci BARs, etc.) via either path. Revisions 1+ dropped the
// 4 GiB identity map and progressively narrowed HHDM coverage, requiring
// the kernel to set up its own page-table entries for MMIO.

#[used]
#[unsafe(link_section = ".limine_requests")]
static BASE_REVISION: BaseRevision = BaseRevision::with_revision(0);

#[used]
#[unsafe(link_section = ".limine_requests")]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static EXEC_ADDRESS_REQUEST: ExecutableAddressRequest = ExecutableAddressRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static MEMORY_MAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

#[cfg(target_arch = "aarch64")]
#[used]
#[unsafe(link_section = ".limine_requests")]
static DTB_REQUEST: DeviceTreeBlobRequest = DeviceTreeBlobRequest::new();

#[cfg(target_arch = "x86_64")]
#[used]
#[unsafe(link_section = ".limine_requests")]
static RSDP_REQUEST: RsdpRequest = RsdpRequest::new();

// Limine kernel cmdline. Equivalent of `chosen.bootargs` on the
// FDT path: lets the QEMU `-append` / OVMF NVRAM boot-arg reach
// the unikernel. Apps key boot-time configuration off the result
// (e.g. `quic.log=events`).
#[cfg(target_arch = "x86_64")]
#[used]
#[unsafe(link_section = ".limine_requests")]
static CMDLINE_REQUEST: ExecutableCmdlineRequest = ExecutableCmdlineRequest::new();

// Limine MP request. The presence of this static tells Limine to
// start every AP during its own pre-boot phase via INIT-SIPI-SIPI
// and park it in long mode, awaiting a `goto_address` write from us.
//
// Default flags (no X2APIC). Combined with treating
// BOOTLOADER_RECLAIMABLE as RESERVED (see memory-map handling above),
// this boots cleanly on both QEMU TCG and GCE KVM + OVMF. The earlier
// reset-loop symptom on GCE was our frame allocator handing out
// Limine's AP-stack memory, not anything about APIC mode.
#[cfg(target_arch = "x86_64")]
#[used]
#[unsafe(link_section = ".limine_requests")]
pub static MP_REQUEST: MpRequest = MpRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests_start")]
static REQUESTS_START: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[unsafe(link_section = ".limine_requests_end")]
static REQUESTS_END: RequestsEndMarker = RequestsEndMarker::new();

// ============================================================================
// Limine entry function
// ============================================================================

unsafe extern "C" {
    fn kernel_boot_from_bootinfo(info: *const BootInfo);
}

// Populated once by `limine_entry` during boot, then treated as
// read-only for the life of the kernel (kernel_boot_from_bootinfo
// only reads).
struct LimineBootInfoCell(core::cell::UnsafeCell<BootInfo>);
// SAFETY: single write on the BSP before `kernel_boot_from_bootinfo`
// is called; immutable afterwards.
unsafe impl Sync for LimineBootInfoCell {}

static LIMINE_BOOT_INFO: LimineBootInfoCell =
    LimineBootInfoCell(core::cell::UnsafeCell::new(BootInfo {
        protocol: Protocol::Limine,
        memory_map_count: 0,
        memory_map: [MemoryRegion {
            base: 0,
            length: 0,
            region_type: 0,
            _pad: 0,
        }; MAX_MEMORY_REGIONS],
        dtb_addr: 0,
        kernel_phys_base: 0,
        kernel_virt_base: 0,
        hhdm_offset: 0,
        rsdp_paddr: 0,
    }));

/// Rust entry point for the Limine boot path, tail-called from
/// `limine_entry_stub` after it has switched to the kernel stack and
/// enabled the SSE/AVX OS-level bits.
///
/// # Safety
///
/// Must be called exactly once, by `limine_entry_stub`, on the BSP
/// before any AP starts. It relies on Limine having satisfied the
/// `.limine_requests` statics in this file. Reads device MMIO
/// (aarch64 FDT/ECAM) and writes the `LIMINE_BOOT_INFO` static, so it
/// must run single-threaded with no concurrent access to that static.
/// Never returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn limine_entry() {
    // Build the BootInfo in a local first; commit to LIMINE_BOOT_INFO once
    // at the end. This avoids forming an `&mut LIMINE_BOOT_INFO` and lets
    // the file build with `static_mut_refs` denied.
    let mut info = BootInfo {
        protocol: Protocol::Limine,
        memory_map_count: 0,
        memory_map: [MemoryRegion {
            base: 0,
            length: 0,
            region_type: 0,
            _pad: 0,
        }; MAX_MEMORY_REGIONS],
        dtb_addr: 0,
        kernel_phys_base: 0,
        kernel_virt_base: 0,
        hhdm_offset: 0,
        rsdp_paddr: 0,
    };

    // HHDM offset.
    if let Some(resp) = HHDM_REQUEST.get_response() {
        info.hhdm_offset = resp.offset();
    }

    // Kernel base addresses (needed by mm::init() to compute phys from virt
    // for the higher-half kernel image).
    if let Some(resp) = EXEC_ADDRESS_REQUEST.get_response() {
        info.kernel_phys_base = resp.physical_base();
        info.kernel_virt_base = resp.virtual_base();
    }

    // Memory map.
    //
    // We mark BOOTLOADER_RECLAIMABLE as RESERVED, NOT available. With
    // the MP request enabled, Limine uses bootloader-reclaimable
    // memory for AP stacks and state — the APs are parked there until
    // we write their `goto_address` fields, and if we hand that memory
    // to our frame allocator and then zero-fill a virtqueue ring into
    // it, the APs triple-fault and take the VM down with them (seen
    // on GCE KVM on 2026-04-16). The spec says we *can* reclaim this
    // region once the kernel is done with Limine, but that would
    // require tracking when it's safe and we don't need the memory
    // badly enough (10 MiB on GCE is a rounding error for our 8 GiB).
    if let Some(resp) = MEMORY_MAP_REQUEST.get_response() {
        let mut count = 0i32;
        for entry in resp.entries() {
            if count as usize >= MAX_MEMORY_REGIONS {
                break;
            }
            let region_type = match entry.entry_type {
                EntryType::USABLE => MEM_AVAILABLE,
                _ => MEM_RESERVED,
            };
            info.memory_map[count as usize] = MemoryRegion {
                base: entry.base,
                length: entry.length,
                region_type,
                _pad: 0,
            };
            count += 1;
        }
        info.memory_map_count = count;
    }

    // x86_64: ACPI RSDP physical address. Limine hands us an
    // HHDM-mapped virtual pointer (base revision 0/1 default), so
    // convert back to physical by subtracting hhdm_offset. On GCE's
    // UEFI boot path the legacy 0xE0000–0xFFFFF BIOS scan in
    // acpi::detect_cpus comes up empty; without this plumbing the
    // kernel silently falls back to single-core.
    #[cfg(target_arch = "x86_64")]
    if let Some(resp) = RSDP_REQUEST.get_response() {
        let virt = resp.address() as u64;
        if virt != 0 && virt >= info.hhdm_offset {
            info.rsdp_paddr = virt - info.hhdm_offset;
        }
    }

    // x86_64: kernel cmdline (Limine equivalent of FDT
    // `chosen.bootargs`). Copy out into the kernel's static buffer
    // so we don't keep a pointer into Limine's bootloader-
    // reclaimable region. Missing response or empty cmdline → no
    // install (`boot_args()` returns `""`).
    #[cfg(target_arch = "x86_64")]
    if let Some(resp) = CMDLINE_REQUEST.get_response() {
        let bytes = resp.cmdline().to_bytes();
        if !bytes.is_empty() {
            kernel_bare::x86_64::boot_args::install(bytes);
        }
    }

    // aarch64: DTB for FDT-based device discovery.
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(resp) = DTB_REQUEST.get_response() {
            info.dtb_addr = resp.dtb_ptr() as u64;
        }
        if info.dtb_addr != 0 {
            unsafe {
                fdt::init(info.dtb_addr);
                let fdt_info = &*fdt::info_ptr();
                if fdt_info.pcie_ecam_base != 0 && fdt_info.pcie_ecam_size != 0 {
                    mmu::map_device_range(fdt_info.pcie_ecam_base, fdt_info.pcie_ecam_size);
                }
            }
        }
    }

    // Commit the populated BootInfo to the static and call into the kernel.
    unsafe {
        core::ptr::write(LIMINE_BOOT_INFO.0.get(), info);
        kernel_boot_from_bootinfo(LIMINE_BOOT_INFO.0.get() as *const BootInfo);
    }
}

// ============================================================================
// Limine MP AP startup (x86_64 only).
//
// `limine_ap_stub` matches Limine's required `fn(&Cpu) -> !` callback
// shape. Limine calls it on each AP once we write the stub's address
// to the corresponding `Cpu::goto_address`; by then the AP is already
// in long mode on Limine's page tables with a 64 KiB stack. We just
// extract the LAPIC ID and forward to the kernel crate's AP entry
// — keeping `limine::mp::Cpu` references out of `kernel`.
// ============================================================================

#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn limine_ap_stub(cpu: &limine::mp::Cpu) -> ! {
    unsafe { kernel_bare::x86_64::smp::ap_entry_via_limine(cpu.lapic_id) }
}

/// Release every non-BSP CPU parked by Limine's MP request into
/// `limine_ap_stub`. Returns the total CPU count Limine reported
/// (including the BSP), or 1 if the MP response is missing.
///
/// no_mangle + extern "C" so boot/entry.rs can call this by linker
/// name without pulling the limine crate into its dep list.
///
/// # Safety
///
/// Must be called once, on the BSP, after the kernel is far enough
/// along to handle APs joining the event loop (APIC and per-CPU state
/// initialised). It writes each AP's `goto_address`, releasing it into
/// `limine_ap_stub`, so it relies on Limine having satisfied
/// `MP_REQUEST` and on the parked APs still being valid.
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn start_aps_via_limine_mp() -> u32 {
    let resp = match MP_REQUEST.get_response() {
        Some(r) => r,
        None => return 1,
    };
    let bsp = resp.bsp_lapic_id();
    let cpus = resp.cpus();
    for cpu in cpus {
        if cpu.lapic_id != bsp {
            cpu.goto_address.write(limine_ap_stub);
        }
    }
    cpus.len() as u32
}
