// kernel/mmu.rs — Dynamic device memory mapping
//
// Adds page table entries on demand for MMIO regions outside the boot
// stub's initial identity map. Used by the PCI BAR scan to make
// high-MMIO BARs accessible (e.g. q35 + SeaBIOS places virtio-net's
// modern config BAR at ~56 TiB when guest RAM > 3 GiB).
//
// aarch64 walks the boot.S L1 table directly (256 KB stack-resident
// table). x86_64 reads CR3 to find the active PML4 — works under both
// the multiboot/PVH boot stub (where CR3 points at boot.S's boot_pml4)
// and Limine (where CR3 points at Limine's higher-half PML4).

// ============================================================================
// aarch64 implementation
// ============================================================================

#[cfg(target_arch = "aarch64")]
mod aarch64 {
    use core::arch::asm;

    use crate::mm;

    // L1 page table set up by boot.S — in .boot_bss, not zeroed by BSS clear.
    unsafe extern "C" {
        static mut boot_l1_table: [u64; 512];
    }

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
        unsafe {
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

                // Skip if already in the first 4GB (mapped as normal-cached by
                // boot.S; the hypervisor's Stage-2 tables override the attribute
                // to device for MMIO regions without guest involvement).
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
                    // Allocate a fresh 4 KB-aligned L2 table from the heap.
                    // `map_device_range` only runs after `mm::init` has set
                    // up the talc heap, so this is safe; on aarch64 phys ==
                    // virt (identity-mapped), so the returned address works
                    // both as the descriptor target and as a writable pointer.
                    let l2_phys = mm::alloc_pages(1);
                    if l2_phys == 0 {
                        return; // heap exhausted
                    }
                    l2 = l2_phys as *mut u64;
                    // alloc_pages does not zero — clear the table before use.
                    core::ptr::write_bytes(l2, 0, 512);

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
                let range_end = if end < gb + (1 << 30) {
                    end
                } else {
                    gb + (1 << 30)
                };

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
}

// ============================================================================
// x86_64 implementation
// ============================================================================

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use core::arch::asm;
    use core::ptr;

    use crate::mm;

    // 4-level paging entry bits.
    const PRESENT: u64 = 1 << 0;
    const WRITABLE: u64 = 1 << 1;
    const PWT: u64 = 1 << 3;
    const PCD: u64 = 1 << 4;
    const PS: u64 = 1 << 7;       // Page Size — set on PD entries to mean 2 MiB block.
    const GLOBAL: u64 = 1 << 8;

    // Address bits in a page table entry. Bits [51:12] hold the
    // physical address; the upper/lower bits hold flags. 52-bit phys
    // addresses are the worst-case for x86_64; AMD/Intel CPUs in
    // practice report MAXPHYADDR ≤ 52.
    const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    const TABLE_FLAGS: u64 = PRESENT | WRITABLE;
    // Strong-UC MMIO: PCD + PWT, global. NOT setting bit 63 (NX):
    // `EFER.NXE` isn't enabled by the boot stub, so NX is reserved
    // and setting it raises #PF with err.bit3 (reserved bits set in
    // page table). boot.S's identity-map entries omit NX for the
    // same reason — staying consistent.
    const MMIO_2MB_FLAGS: u64 = PRESENT | WRITABLE | PWT | PCD | PS | GLOBAL;

    fn read_cr3_phys() -> u64 {
        let cr3: u64;
        // SAFETY: reading CR3 is unconditionally safe in kernel mode.
        unsafe {
            asm!("mov {0}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        }
        cr3 & ADDR_MASK
    }

    fn flush_tlb_all() {
        // Reload CR3 — flushes every non-global entry, picks up our
        // newly-installed PML4/PDPT/PD entries. Global entries
        // (PTE_G) survive the reload, but the entries we install
        // here are *new* — they weren't cached, so the next walk
        // finds them either way.
        // SAFETY: CR3 read+write is unconditionally safe in kernel mode.
        unsafe {
            let cr3: u64;
            asm!("mov {0}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
            asm!("mov cr3, {0}", in(reg) cr3, options(nomem, nostack, preserves_flags));
        }
    }

    /// Install identity mappings for `[phys_base, phys_base + size)`
    /// as strong-UC MMIO, 2 MiB granularity. Walks the active PML4
    /// (via CR3), allocating intermediate PDPT / PD tables from the
    /// kernel heap on demand. Idempotent: re-mapping the same range
    /// just overwrites the leaf entry with identical flags.
    pub unsafe fn map_device_range(phys_base: u64, size: u64) {
        unsafe {
            if size == 0 {
                return;
            }

            let base_2m = phys_base & !0x1F_FFFF_u64;
            let end_2m = (phys_base + size + 0x1F_FFFF) & !0x1F_FFFF_u64;

            let pml4_phys = read_cr3_phys();
            let pml4 = mm::phys_to_virt(pml4_phys) as *mut u64;

            let mut addr = base_2m;
            while addr < end_2m {
                let pml4_idx = ((addr >> 39) & 0x1FF) as usize;
                let pdpt_idx = ((addr >> 30) & 0x1FF) as usize;
                let pd_idx = ((addr >> 21) & 0x1FF) as usize;

                // PML4 → PDPT
                let pml4_entry = ptr::read_volatile(pml4.add(pml4_idx));
                let pdpt_phys: u64 = if (pml4_entry & PRESENT) != 0 {
                    pml4_entry & ADDR_MASK
                } else {
                    let p = mm::alloc_pages(1);
                    if p == 0 {
                        return;
                    }
                    ptr::write_bytes(mm::phys_to_virt(p), 0, 4096);
                    ptr::write_volatile(pml4.add(pml4_idx), p | TABLE_FLAGS);
                    p
                };

                // PDPT → PD
                let pdpt = mm::phys_to_virt(pdpt_phys) as *mut u64;
                let pdpt_entry = ptr::read_volatile(pdpt.add(pdpt_idx));
                if (pdpt_entry & PRESENT) != 0 && (pdpt_entry & PS) != 0 {
                    // Already mapped as a 1 GiB page (e.g. by Limine's
                    // HHDM). The 2 MiB slice we'd install lives inside
                    // it; leave the existing mapping in place.
                    addr += 1 << 21;
                    continue;
                }
                let pd_phys: u64 = if (pdpt_entry & PRESENT) != 0 {
                    pdpt_entry & ADDR_MASK
                } else {
                    let p = mm::alloc_pages(1);
                    if p == 0 {
                        return;
                    }
                    ptr::write_bytes(mm::phys_to_virt(p), 0, 4096);
                    ptr::write_volatile(pdpt.add(pdpt_idx), p | TABLE_FLAGS);
                    p
                };

                // PD → 2 MiB block (identity)
                let pd = mm::phys_to_virt(pd_phys) as *mut u64;
                ptr::write_volatile(pd.add(pd_idx), addr | MMIO_2MB_FLAGS);

                addr += 1 << 21;
            }

            flush_tlb_all();
        }
    }

    /// Walk `table[idx]`; if absent, allocate + zero a fresh next-level
    /// table and install it. Returns the next-level table's *virtual*
    /// pointer (HHDM), or null on OOM.
    unsafe fn next_table(table: *mut u64, idx: usize) -> *mut u64 {
        unsafe {
            let entry = ptr::read_volatile(table.add(idx));
            // A present huge-page entry (PS at the PDPT/PD level) maps a
            // 1 GiB/2 MiB block, not a sub-table; descending would mis-read
            // the data frame as a page table and corrupt memory. The
            // dedicated stacks region is virgin so this never fires in
            // practice, but reject it rather than rely on that invariant.
            if (entry & PRESENT) != 0 && (entry & PS) != 0 {
                return ptr::null_mut();
            }
            let next_phys = if (entry & PRESENT) != 0 {
                entry & ADDR_MASK
            } else {
                let p = mm::alloc_pages(1); // physical
                if p == 0 {
                    return ptr::null_mut();
                }
                ptr::write_bytes(mm::phys_to_virt(p), 0, 4096);
                ptr::write_volatile(table.add(idx), p | TABLE_FLAGS);
                p
            };
            mm::phys_to_virt(next_phys) as *mut u64
        }
    }

    /// Map `count` 4 KiB pages `[phys_base ..]` at `[virt_base ..]` as
    /// normal cached writable kernel memory, creating PDPT/PD/PT tables
    /// on demand. Unlike `map_device_range` this descends to the 4 KiB
    /// PT level, so callers can leave individual pages unmapped (e.g. a
    /// stack guard page). Caller serializes against concurrent callers —
    /// the page tables are shared across cores. Returns false on OOM.
    pub unsafe fn map_pages_4k(virt_base: u64, phys_base: u64, count: usize) -> bool {
        unsafe {
            let pml4 = mm::phys_to_virt(read_cr3_phys()) as *mut u64;
            for i in 0..count {
                let virt = virt_base + (i as u64) * 4096;
                let phys = phys_base + (i as u64) * 4096;
                let pdpt = next_table(pml4, ((virt >> 39) & 0x1FF) as usize);
                if pdpt.is_null() {
                    return false;
                }
                let pd = next_table(pdpt, ((virt >> 30) & 0x1FF) as usize);
                if pd.is_null() {
                    return false;
                }
                let pt = next_table(pd, ((virt >> 21) & 0x1FF) as usize);
                if pt.is_null() {
                    return false;
                }
                // PRESENT | WRITABLE, cached. No NX (EFER.NXE is off; see
                // MMIO_2MB_FLAGS note).
                ptr::write_volatile(pt.add(((virt >> 12) & 0x1FF) as usize), phys | TABLE_FLAGS);
            }
            flush_tlb_all();
            true
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Map a range of physical addresses as device memory.
///
/// 2 MiB-granular identity mapping with strong-UC attributes; safe to
/// call repeatedly for the same range. Allocates from the kernel heap,
/// so it must run after `mm::init`.
pub fn map_device_range(phys_base: u64, size: u64) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        aarch64::map_device_range(phys_base, size);
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        x86_64::map_device_range(phys_base, size);
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let _ = (phys_base, size);
    }
}

/// Map `count` 4 KiB pages `[phys_base ..]` at `[virt_base ..]` as
/// normal cached writable kernel memory (x86_64). Used to lay out
/// worker stacks in a dedicated VA region with an unmapped guard page
/// below each, so a stack overflow faults at the guard instead of
/// silently corrupting neighbouring memory. Returns `false` on OOM or
/// on non-x86_64 (the caller then uses an unguarded stack — no
/// regression). `# Safety`: installs page-table entries; the caller
/// must serialize concurrent callers (the tables are shared) and ensure
/// `virt_base` is in a region not otherwise mapped.
pub unsafe fn map_pages_4k(virt_base: u64, phys_base: u64, count: usize) -> bool {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        x86_64::map_pages_4k(virt_base, phys_base, count)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (virt_base, phys_base, count);
        false
    }
}
