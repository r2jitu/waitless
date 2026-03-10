#pragma once
// kernel/boot_shim.h — Boot protocol shims
//
// Each shim takes the raw boot_info_addr from the assembly entry point
// and populates a BootInfo struct.

#include "kernel/boot_info.h"

namespace boot {

#if defined(__x86_64__)
// Detect PVH vs Multiboot2 vs fallback, populate BootInfo.
void shim_x86(BootInfo *info, uint64_t boot_info_addr);
#elif defined(__aarch64__)
// Populate from FDT memory node. fdt::init() must have been called first.
void shim_fdt(BootInfo *info, uint64_t dtb_addr);
#endif

} // namespace boot
