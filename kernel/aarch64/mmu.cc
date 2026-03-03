// kernel/aarch64/mmu.cc — Dynamic device memory mapping
//
// Adds L2 page table entries for device MMIO regions above 4GB.
// Uses 2MB block descriptors for precise coverage.
//
// The boot.S L1 table has 512 entries (each 1GB). To map a sub-1GB region
// with 2MB granularity, we replace the L1 block entry with a table entry
// pointing to an L2 table (512 × 2MB blocks = 1GB).

#include "kernel/aarch64/mmu.h"

namespace mmu {

// L1 page table set up by boot.S — in .boot_bss, not zeroed by BSS clear.
extern "C" uint64_t boot_l1_table[];

// Pool of L2 tables in .boot_bss (survive BSS zero, pre-MMU-enable).
// Each L2 table = 4KB = 512 entries, each covering 2MB.
// 4 tables supports 4 separate 1GB regions (ECAM + a few BAR regions).
static constexpr int MAX_L2_TABLES = 4;

// L2 tables must be in .boot_bss (not .bss) because boot.S zeros .bss
// AFTER enabling the MMU using boot_l1_table. If L2 tables were in .bss,
// they'd be zeroed while the MMU is live, causing page faults.
static uint64_t l2_tables[MAX_L2_TABLES][512]
    __attribute__((aligned(4096), section(".boot_bss")));
static int l2_next = 0;

// Descriptor bits (same as boot.S):
//   L1 table entry:  [addr of L2 table | 0x3] (bits[1:0] = 0b11 = table)
//   L2 block entry:  [PA | AttrIdx=0 | AF=1 | valid] = PA | 0x0401
//     AttrIdx=0 → MAIR attr0 = 0x00 = device nGnRnE
//     AF=1 → bit[10] = access flag
//     valid → bit[0] = 1
//     block → bit[1] = 0 (2MB block, not table)
static constexpr uint64_t L1_TABLE_DESC  = 0x3;
static constexpr uint64_t L2_DEVICE_BLOCK = 0x0401;

void map_device_range(uint64_t phys_base, uint64_t size) {
    if (size == 0) return;

    // Align phys_base down to 2MB, adjust size
    uint64_t base_2m = phys_base & ~((uint64_t)0x1FFFFF);
    uint64_t end     = (phys_base + size + 0x1FFFFF) & ~((uint64_t)0x1FFFFF);

    // Process each 1GB region that overlaps [base_2m, end)
    uint64_t gb_start = base_2m & ~((uint64_t)0x3FFFFFFF);  // 1GB-aligned
    for (uint64_t gb = gb_start; gb < end; gb += (uint64_t)1 << 30) {
        uint64_t l1_idx = gb >> 30;
        if (l1_idx >= 512) continue;

        // Skip if already in the first 4GB (mapped as normal-cached by boot.S;
        // VZ Stage-2 overrides to device for MMIO regions)
        if (l1_idx < 4) continue;

        // Check if L1 entry already has a table descriptor (from previous call)
        uint64_t l1_entry = boot_l1_table[l1_idx];
        uint64_t* l2;

        if ((l1_entry & 0x3) == 0x3) {
            // Already a table descriptor — reuse the L2 table
            l2 = reinterpret_cast<uint64_t*>(l1_entry & ~(uint64_t)0xFFF);
        } else {
            // Need a new L2 table
            if (l2_next >= MAX_L2_TABLES) return;  // out of L2 tables
            l2 = l2_tables[l2_next++];

            // If there was a block descriptor, preserve it by filling
            // the L2 table with equivalent 2MB blocks
            if (l1_entry & 0x1) {
                uint64_t block_pa    = l1_entry & ~(uint64_t)0x3FFFFFFF;
                uint64_t block_attrs = l1_entry & 0xFFF;
                // Convert L1 block attrs to L2 block attrs (same format)
                for (int i = 0; i < 512; i++) {
                    l2[i] = (block_pa + (uint64_t)i * (2 << 20)) | block_attrs;
                }
            }

            // Point L1 entry at the new L2 table
            boot_l1_table[l1_idx] = ((uint64_t)l2) | L1_TABLE_DESC;
        }

        // Fill in the device entries for the 2MB blocks within this 1GB region
        uint64_t range_start = (base_2m > gb) ? base_2m : gb;
        uint64_t range_end   = (end < gb + ((uint64_t)1 << 30)) ? end : gb + ((uint64_t)1 << 30);

        for (uint64_t addr = range_start; addr < range_end; addr += (2 << 20)) {
            int l2_idx = (int)((addr - gb) >> 21);
            l2[l2_idx] = addr | L2_DEVICE_BLOCK;
        }
    }

    // Ensure table writes are visible, then invalidate TLB
    asm volatile("dsb sy; tlbi vmalle1; dsb sy; isb" ::: "memory");
}

} // namespace mmu
