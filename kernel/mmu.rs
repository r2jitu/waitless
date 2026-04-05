// kernel/mmu.rs — Dynamic device memory mapping for ARM64
//
// Adds L2 page table entries for device MMIO regions above 4GB.
// Uses 2MB block descriptors for precise coverage.
//
// The boot.S L1 table has 512 entries (each 1GB). To map a sub-1GB region
// with 2MB granularity, we replace the L1 block entry with a table entry
// pointing to an L2 table (512 × 2MB blocks = 1GB).
//
// On x86_64 this module provides a no-op stub.

#![no_std]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(static_mut_refs)]

// ============================================================================
// aarch64 implementation
// ============================================================================

#[cfg(target_arch = "aarch64")]
mod aarch64 {
    use core::arch::asm;

    // L1 page table set up by boot.S — in .boot_bss, not zeroed by BSS clear.
    unsafe extern "C" {
        static mut boot_l1_table: [u64; 512];
    }

    // Pool of L2 tables in .boot_bss (survive BSS zero, pre-MMU-enable).
    // Each L2 table = 4KB = 512 entries, each covering 2MB.
    // 4 tables supports 4 separate 1GB regions (ECAM + a few BAR regions).
    const MAX_L2_TABLES: usize = 4;

    // L2 tables must be in .boot_bss (not .bss) because boot.S zeros .bss
    // AFTER enabling the MMU using boot_l1_table. If L2 tables were in .bss,
    // they'd be zeroed while the MMU is live, causing page faults.
    #[unsafe(link_section = ".boot_bss")]
    static mut L2_TABLES: [[u64; 512]; MAX_L2_TABLES] = [[0; 512]; MAX_L2_TABLES];
    static mut L2_NEXT: usize = 0;

    // Descriptor bits (same as boot.S):
    //   L1 table entry:  [addr of L2 table | 0x3] (bits[1:0] = 0b11 = table)
    //   L2 block entry:  [PA | AttrIdx=0 | AF=1 | valid] = PA | 0x0401
    //     AttrIdx=0 → MAIR attr0 = 0x00 = device nGnRnE
    //     AF=1 → bit[10] = access flag
    //     valid → bit[0] = 1
    //     block → bit[1] = 0 (2MB block, not table)
    const L1_TABLE_DESC: u64 = 0x3;
    const L2_DEVICE_BLOCK: u64 = 0x0401;

    pub unsafe fn map_device_range(phys_base: u64, size: u64) {
        if size == 0 {
            return;
        }

        // Align phys_base down to 2MB, adjust size
        let base_2m = phys_base & !0x1F_FFFF_u64;
        let end = (phys_base + size + 0x1F_FFFF) & !0x1F_FFFF_u64;

        // Process each 1GB region that overlaps [base_2m, end)
        let gb_start = base_2m & !0x3FFF_FFFF_u64; // 1GB-aligned
        let mut gb = gb_start;
        while gb < end {
            let l1_idx = (gb >> 30) as usize;
            if l1_idx >= 512 {
                gb += 1 << 30;
                continue;
            }

            // Skip if already in the first 4GB (mapped as normal-cached by boot.S;
            // VZ Stage-2 overrides to device for MMIO regions)
            if l1_idx < 4 {
                gb += 1 << 30;
                continue;
            }

            // Check if L1 entry already has a table descriptor (from previous call)
            let l1_entry = boot_l1_table[l1_idx];
            let l2: *mut u64;

            if (l1_entry & 0x3) == 0x3 {
                // Already a table descriptor — reuse the L2 table
                l2 = (l1_entry & !0xFFF_u64) as *mut u64;
            } else {
                // Need a new L2 table
                if L2_NEXT >= MAX_L2_TABLES {
                    return; // out of L2 tables
                }
                l2 = L2_TABLES[L2_NEXT].as_mut_ptr();
                L2_NEXT += 1;

                // If there was a block descriptor, preserve it by filling
                // the L2 table with equivalent 2MB blocks
                if (l1_entry & 0x1) != 0 {
                    let block_pa = l1_entry & !0x3FFF_FFFF_u64;
                    let block_attrs = l1_entry & 0xFFF;
                    for i in 0..512 {
                        *l2.add(i) = (block_pa + (i as u64) * (2 << 20)) | block_attrs;
                    }
                }

                // Point L1 entry at the new L2 table
                boot_l1_table[l1_idx] = (l2 as u64) | L1_TABLE_DESC;
            }

            // Fill in the device entries for the 2MB blocks within this 1GB region
            let range_start = if base_2m > gb { base_2m } else { gb };
            let range_end = if end < gb + (1 << 30) { end } else { gb + (1 << 30) };

            let mut addr = range_start;
            while addr < range_end {
                let l2_idx = ((addr - gb) >> 21) as usize;
                *l2.add(l2_idx) = addr | L2_DEVICE_BLOCK;
                addr += 2 << 20;
            }

            gb += 1 << 30;
        }

        // Ensure table writes are visible, then invalidate TLB
        asm!("dsb sy", "tlbi vmalle1", "dsb sy", "isb", options(nostack));
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Map a range of physical addresses as device memory.
/// On x86_64, this is a no-op (all physical memory is identity-mapped).
pub fn mmu_map_device_range(phys_base: u64, size: u64) {
    #[cfg(target_arch = "aarch64")]
    unsafe { aarch64::map_device_range(phys_base, size); }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (phys_base, size);
    }
}
