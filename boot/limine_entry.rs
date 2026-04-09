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

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }

extern crate kernel;
use kernel::types::{BootInfo, MemoryRegion, Protocol, MEM_AVAILABLE, MEM_RESERVED, MAX_MEMORY_REGIONS};

use limine::BaseRevision;
use limine::memory_map::EntryType;
use limine::request::{
    ExecutableAddressRequest, HhdmRequest, MemoryMapRequest, RequestsEndMarker,
    RequestsStartMarker,
};

#[cfg(target_arch = "aarch64")]
use limine::request::DeviceTreeBlobRequest;
#[cfg(target_arch = "x86_64")]
use limine::request::RsdpRequest;

// x86_64 SSE enable stub — Limine doesn't enable SSE before calling our entry.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".section .text",
    ".code64",
    ".global limine_entry_stub",
    "limine_entry_stub:",
    "    mov %cr4, %rax",
    "    or  $(1 << 9) | (1 << 10), %rax",
    "    mov %rax, %cr4",
    "    xor %rbp, %rbp",
    "    and $-16, %rsp",
    "    call limine_entry",
    "1: cli",
    "    hlt",
    "    jmp 1b",
    options(att_syntax),
);

#[cfg(target_arch = "aarch64")]
use kernel::aarch64::{fdt, mmu};

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

static mut LIMINE_BOOT_INFO: BootInfo = BootInfo {
    protocol: Protocol::Limine,
    memory_map_count: 0,
    memory_map: [MemoryRegion { base: 0, length: 0, region_type: 0, _pad: 0 }; MAX_MEMORY_REGIONS],
    dtb_addr: 0,
    kernel_phys_base: 0,
    kernel_virt_base: 0,
    hhdm_offset: 0,
};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn limine_entry() {
    // Build the BootInfo in a local first; commit to LIMINE_BOOT_INFO once
    // at the end. This avoids forming an `&mut LIMINE_BOOT_INFO` and lets
    // the file build with `static_mut_refs` denied.
    let mut info = BootInfo {
        protocol: Protocol::Limine,
        memory_map_count: 0,
        memory_map: [MemoryRegion { base: 0, length: 0, region_type: 0, _pad: 0 }; MAX_MEMORY_REGIONS],
        dtb_addr: 0,
        kernel_phys_base: 0,
        kernel_virt_base: 0,
        hhdm_offset: 0,
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
    if let Some(resp) = MEMORY_MAP_REQUEST.get_response() {
        let mut count = 0i32;
        for entry in resp.entries() {
            if count as usize >= MAX_MEMORY_REGIONS { break; }
            let region_type = match entry.entry_type {
                EntryType::USABLE | EntryType::BOOTLOADER_RECLAIMABLE => MEM_AVAILABLE,
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
        core::ptr::write(&raw mut LIMINE_BOOT_INFO, info);
        kernel_boot_from_bootinfo(&raw const LIMINE_BOOT_INFO);
    }
}
