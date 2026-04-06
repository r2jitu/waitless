// kernel/limine_entry.rs — Limine boot protocol entry point (Rust)
//
// When the kernel is loaded by the Limine bootloader, it calls limine_entry()
// instead of the normal boot.S _start.  Limine has already set up:
//   - 64-bit mode (x86) or EL1 (aarch64), MMU on, paging enabled
//   - BSS zeroed, valid stack
//   - Identity mapping of first 4GB + HHDM
//
// This file declares Limine requests in the .limine_requests section.
// Limine scans for these tagged structs and fills in response pointers
// before calling our entry point.

#![no_std]
#![allow(static_mut_refs)]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }

extern crate kernel;
use kernel::types::{BootInfo, MemoryRegion, Protocol, MEM_AVAILABLE, MEM_RESERVED, MAX_MEMORY_REGIONS};

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
    "    call limine_entry_cpp",
    "1: cli",
    "    hlt",
    "    jmp 1b",
    options(att_syntax),
);
#[cfg(target_arch = "aarch64")]
use kernel::aarch64::{fdt, mmu};

// ============================================================================
// Limine protocol constants and struct types
// ============================================================================

const COMMON_MAGIC_0: u64 = 0xc7b1dd30df4c8b88;
const COMMON_MAGIC_1: u64 = 0x0a82e883a194f07b;

const MEMMAP_USABLE: u64 = 0;
const MEMMAP_BOOTLOADER_RECLAIMABLE: u64 = 5;

// Limine response structs — populated by the bootloader before entry.
#[repr(C)]
struct MemmapEntry {
    base: u64,
    length: u64,
    entry_type: u64,
}

#[repr(C)]
struct MemmapResponse {
    revision: u64,
    entry_count: u64,
    entries: *const *const MemmapEntry,
}

#[repr(C)]
struct MemmapRequest {
    id: [u64; 4],
    revision: u64,
    response: *const MemmapResponse,
}

#[repr(C)]
struct EntryPointResponse {
    revision: u64,
}

#[repr(C)]
struct EntryPointRequest {
    id: [u64; 4],
    revision: u64,
    response: *const EntryPointResponse,
    entry: unsafe extern "C" fn(),
}

#[repr(C)]
struct HhdmResponse {
    revision: u64,
    offset: u64,
}

#[repr(C)]
struct HhdmRequest {
    id: [u64; 4],
    revision: u64,
    response: *const HhdmResponse,
}

#[repr(C)]
struct KernelAddressResponse {
    revision: u64,
    physical_base: u64,
    virtual_base: u64,
}

#[repr(C)]
struct KernelAddressRequest {
    id: [u64; 4],
    revision: u64,
    response: *const KernelAddressResponse,
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
struct DtbResponse {
    revision: u64,
    dtb_ptr: u64, // void* in C, treated as u64 for pointer-width independence
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
struct DtbRequest {
    id: [u64; 4],
    revision: u64,
    response: *const DtbResponse,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct RsdpResponse {
    revision: u64,
    address: u64, // void* in C
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct RsdpRequest {
    id: [u64; 4],
    revision: u64,
    response: *const RsdpResponse,
}

// ============================================================================
// Limine request structs (placed in .limine_requests section)
// ============================================================================

// The #[used] attribute prevents the linker from stripping these statics.
// The #[link_section] attributes place them in the correct ELF sections
// that Limine scans for requests.

// Section start marker
#[used]
#[unsafe(link_section = ".limine_requests_start")]
static LIMINE_START_MARKER: [u64; 4] = [
    0xf6b8f4b39de7d1ae, 0xfab91a6940fcb9cf,
    0x785c6ed015d3e316, 0x181e920a7852b9d9,
];

// Base revision (revision 3)
#[used]
#[unsafe(link_section = ".limine_requests")]
static LIMINE_BASE_REVISION: [u64; 3] = [
    0xf9562b2d5c95a6c8, 0x6a7b384944536bdc, 3,
];

// Memory map request
#[used]
#[unsafe(link_section = ".limine_requests")]
static mut MEMMAP_REQUEST: MemmapRequest = MemmapRequest {
    id: [COMMON_MAGIC_0, COMMON_MAGIC_1, 0x67cf3d9d378a806f, 0xe304acdfc50c3c62],
    revision: 0,
    response: core::ptr::null(),
};

// Entry point request
// On x86_64, the stub (limine_boot.S) enables SSE before calling Rust.
// On aarch64, Limine calls limine_entry_cpp directly.
#[used]
#[unsafe(link_section = ".limine_requests")]
static mut ENTRY_POINT_REQUEST: EntryPointRequest = EntryPointRequest {
    id: [COMMON_MAGIC_0, COMMON_MAGIC_1, 0x13d86c035a1cd3e1, 0x2b0caa89d8f3026a],
    revision: 0,
    response: core::ptr::null(),
    #[cfg(target_arch = "x86_64")]
    entry: limine_entry_stub,
    #[cfg(target_arch = "aarch64")]
    entry: limine_entry_cpp,
};

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn limine_entry_stub();
}

// HHDM request
#[used]
#[unsafe(link_section = ".limine_requests")]
static mut HHDM_REQUEST: HhdmRequest = HhdmRequest {
    id: [COMMON_MAGIC_0, COMMON_MAGIC_1, 0x48dcf1cb8ad2b852, 0x63984e959a98244b],
    revision: 0,
    response: core::ptr::null(),
};

// Kernel address request
#[used]
#[unsafe(link_section = ".limine_requests")]
static mut KADDR_REQUEST: KernelAddressRequest = KernelAddressRequest {
    id: [COMMON_MAGIC_0, COMMON_MAGIC_1, 0x71ba76863cc55f63, 0xb2644a48c516a487],
    revision: 0,
    response: core::ptr::null(),
};

// DTB request (aarch64 only)
#[cfg(target_arch = "aarch64")]
#[used]
#[unsafe(link_section = ".limine_requests")]
static mut DTB_REQUEST: DtbRequest = DtbRequest {
    id: [COMMON_MAGIC_0, COMMON_MAGIC_1, 0xb40ddb48fb54bac7, 0x545081493f81ffb7],
    revision: 0,
    response: core::ptr::null(),
};

// RSDP request (x86 only)
#[cfg(target_arch = "x86_64")]
#[used]
#[unsafe(link_section = ".limine_requests")]
static mut RSDP_REQUEST: RsdpRequest = RsdpRequest {
    id: [COMMON_MAGIC_0, COMMON_MAGIC_1, 0xc5e77b6b397e7b43, 0x27637845accdcf3c],
    revision: 0,
    response: core::ptr::null(),
};

// Section end marker
#[used]
#[unsafe(link_section = ".limine_requests_end")]
static LIMINE_END_MARKER: [u64; 2] = [
    0xadc0e0531bb10d03, 0x9572709f31764c62,
];

// ============================================================================
// External kernel functions (in different static library)
// ============================================================================

unsafe extern "C" {
    fn kernel_boot_from_bootinfo(info: *const BootInfo);
}

// ============================================================================
// Limine entry function
// ============================================================================

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
pub extern "C" fn limine_entry_cpp() {
    unsafe {
        LIMINE_BOOT_INFO.protocol = Protocol::Limine;
        LIMINE_BOOT_INFO.memory_map_count = 0;
        LIMINE_BOOT_INFO.dtb_addr = 0;
        LIMINE_BOOT_INFO.kernel_phys_base = 0;
        LIMINE_BOOT_INFO.kernel_virt_base = 0;
        LIMINE_BOOT_INFO.hhdm_offset = 0;

        // HHDM offset — Limine revision 3 dropped identity mapping of first 4GB.
        // All physical memory must be accessed via HHDM: virt = hhdm_offset + phys.
        let hhdm_resp = core::ptr::read_volatile(&HHDM_REQUEST.response);
        if !hhdm_resp.is_null() {
            LIMINE_BOOT_INFO.hhdm_offset = (*hhdm_resp).offset;
        }

        // Kernel address — needed by mm::init() to compute physical addresses.
        let kaddr_resp = core::ptr::read_volatile(&KADDR_REQUEST.response);
        if !kaddr_resp.is_null() {
            LIMINE_BOOT_INFO.kernel_phys_base = (*kaddr_resp).physical_base;
            LIMINE_BOOT_INFO.kernel_virt_base = (*kaddr_resp).virtual_base;
        }

        // Memory map
        let memmap_resp = core::ptr::read_volatile(&MEMMAP_REQUEST.response);
        if !memmap_resp.is_null() {
            let resp = &*memmap_resp;
            let mut count = 0i32;
            for i in 0..resp.entry_count {
                if count as usize >= MAX_MEMORY_REGIONS { break; }
                let entry = *resp.entries.add(i as usize);
                LIMINE_BOOT_INFO.memory_map[count as usize] = MemoryRegion {
                    base: (*entry).base,
                    length: (*entry).length,
                    region_type: match (*entry).entry_type {
                        MEMMAP_USABLE | MEMMAP_BOOTLOADER_RECLAIMABLE => MEM_AVAILABLE,
                        _ => MEM_RESERVED,
                    },
                    _pad: 0,
                };
                count += 1;
            }
            LIMINE_BOOT_INFO.memory_map_count = count;
        }

        // aarch64: DTB for FDT-based device discovery
        #[cfg(target_arch = "aarch64")]
        {
            let dtb_resp = core::ptr::read_volatile(&DTB_REQUEST.response);
            if !dtb_resp.is_null() {
                LIMINE_BOOT_INFO.dtb_addr = (*dtb_resp).dtb_ptr;
            }

            // Parse FDT and map PCIe ECAM before serial::init()
            if LIMINE_BOOT_INFO.dtb_addr != 0 {
                fdt::init(LIMINE_BOOT_INFO.dtb_addr);
                let info = &*fdt::info_ptr();
                if info.pcie_ecam_base != 0 && info.pcie_ecam_size != 0 {
                    mmu::map_device_range(info.pcie_ecam_base, info.pcie_ecam_size);
                }
            }
        }

        kernel_boot_from_bootinfo(&LIMINE_BOOT_INFO);
    }
}
