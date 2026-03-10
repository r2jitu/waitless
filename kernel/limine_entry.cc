// kernel/limine_entry.cc — Limine boot protocol entry point
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

#include "kernel/boot_info.h"
#include "kernel/limine.h"

#if defined(__aarch64__)
#include "kernel/aarch64/mmu.h"
#include "kernel/fdt.h"
#endif

// Forward declarations
extern "C" void kernel_boot_from_bootinfo(boot::BootInfo *info);
static void limine_entry();

// ---- Limine request structs (placed in .limine_requests section) ------------

// Section start marker
[[gnu::used, gnu::section(".limine_requests_start")]]
static volatile uint64_t limine_start_marker[4] = {
    0xf6b8f4b39de7d1ae, 0xfab91a6940fcb9cf,
    0x785c6ed015d3e316, 0x181e920a7852b9d9};

// Base revision (revision 3)
[[gnu::used, gnu::section(".limine_requests")]]
static volatile uint64_t limine_base_revision[3] = {
    0xf9562b2d5c95a6c8, 0x6a7b384944536bdc, 3};

// Memory map request
[[gnu::used, gnu::section(".limine_requests")]]
static volatile limine::MemmapRequest memmap_request;

// Entry point request — entry field must be populated at link time so
// Limine knows to call limine_entry() instead of _start.
[[gnu::used, gnu::section(".limine_requests")]]
static volatile limine::EntryPointRequest entry_point_request = {
    {limine::COMMON_MAGIC_0, limine::COMMON_MAGIC_1, 0x13d86c035a1cd3e1,
     0x2b0caa89d8f3026a},
    0,       // revision
    nullptr, // response (filled by Limine)
    limine_entry,
};

// HHDM request
[[gnu::used, gnu::section(".limine_requests")]]
static volatile limine::HhdmRequest hhdm_request;

// Kernel address request
[[gnu::used, gnu::section(".limine_requests")]]
static volatile limine::KernelAddressRequest kaddr_request;

#if defined(__aarch64__)
// DTB request (aarch64 only)
[[gnu::used, gnu::section(".limine_requests")]]
static volatile limine::DtbRequest dtb_request;
#else
// RSDP request (x86 only)
[[gnu::used, gnu::section(".limine_requests")]]
static volatile limine::RsdpRequest rsdp_request;
#endif

// Section end marker
[[gnu::used, gnu::section(".limine_requests_end")]]
static volatile uint64_t limine_end_marker[2] = {
    0xadc0e0531bb10d03, 0x9572709f31764c62};

// ---- Limine entry function --------------------------------------------------

static boot::BootInfo limine_boot_info;

static void limine_entry() {
  limine_boot_info.protocol = boot::Protocol::LIMINE;
  limine_boot_info.memory_map_count = 0;
  limine_boot_info.dtb_addr = 0;

  // Memory map
  if (memmap_request.response) {
    auto *resp = memmap_request.response;
    int count = 0;
    for (uint64_t i = 0;
         i < resp->entry_count && count < boot::MAX_MEMORY_REGIONS; i++) {
      auto *e = resp->entries[i];
      limine_boot_info.memory_map[count].base = e->base;
      limine_boot_info.memory_map[count].length = e->length;
      switch (e->type) {
      case limine::MEMMAP_USABLE:
      case limine::MEMMAP_BOOTLOADER_RECLAIMABLE:
        limine_boot_info.memory_map[count].type =
            boot::MemoryRegion::AVAILABLE;
        break;
      default:
        limine_boot_info.memory_map[count].type = boot::MemoryRegion::RESERVED;
        break;
      }
      limine_boot_info.memory_map[count]._pad = 0;
      count++;
    }
    limine_boot_info.memory_map_count = count;
  }

#if defined(__aarch64__)
  // DTB for FDT-based device discovery
  if (dtb_request.response) {
    limine_boot_info.dtb_addr =
        reinterpret_cast<uint64_t>(dtb_request.response->dtb_ptr);
  }

  // Parse FDT and map PCIe ECAM before serial::init()
  if (limine_boot_info.dtb_addr != 0) {
    fdt::init(limine_boot_info.dtb_addr);
    const fdt::Info &fdt_info = fdt::info();
    if (fdt_info.pcie_ecam_base != 0 && fdt_info.pcie_ecam_size != 0) {
      mmu::map_device_range(fdt_info.pcie_ecam_base, fdt_info.pcie_ecam_size);
    }
  }
#endif

  kernel_boot_from_bootinfo(&limine_boot_info);
}
