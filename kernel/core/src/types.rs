// kernel/types.rs — Shared boot-time types used across kernel crates.
//
// BootInfo, MemoryRegion, and Protocol are used by entry.rs (boot
// orchestration), mm.rs (memory manager), and limine_entry.rs (Limine
// boot protocol).  Defining them once eliminates duplication and
// provides compile-time layout guarantees.

pub const MAX_MEMORY_REGIONS: usize = 64;
pub const MEM_AVAILABLE: u32 = 1;
pub const MEM_RESERVED: u32 = 2;

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Protocol {
    Unknown = 0,
    Multiboot2 = 1,
    Pvh = 2,
    Fdt = 3,
    Limine = 4,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemoryRegion {
    pub base: u64,
    pub length: u64,
    pub region_type: u32,
    pub _pad: u32,
}

#[repr(C)]
pub struct BootInfo {
    pub protocol: Protocol,
    pub memory_map_count: i32,
    pub memory_map: [MemoryRegion; MAX_MEMORY_REGIONS],
    pub dtb_addr: u64,
    pub kernel_phys_base: u64,
    pub kernel_virt_base: u64,
    pub hhdm_offset: u64,
    /// x86_64 ACPI RSDP physical address, as supplied by the boot
    /// protocol (Limine RSDP request, PVH start_info, etc). 0 means
    /// "unknown — fall back to scanning the BIOS area". The legacy
    /// 0xE0000–0xFFFFF scan only works under SeaBIOS; UEFI firmware
    /// (e.g. GCE's OVMF path) puts the RSDP elsewhere and the scan
    /// comes up empty, so we ignore ACPI and boot single-core.
    pub rsdp_paddr: u64,
}

impl BootInfo {
    pub const fn zeroed() -> Self {
        BootInfo {
            protocol: Protocol::Unknown,
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
        }
    }
}
