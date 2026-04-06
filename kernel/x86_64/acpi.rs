#![allow(unsafe_op_in_unsafe_fn)]
// kernel/x86_64/acpi.rs — Minimal ACPI parser for CPU topology.
//
// Finds RSDP in BIOS memory, parses RSDT, finds MADT, extracts
// Local APIC entries to discover CPU count and APIC IDs.

use crate::serial;

/// ACPI RSDP signature: "RSD PTR "
const RSDP_SIG: [u8; 8] = *b"RSD PTR ";

/// MADT signature: "APIC"
const MADT_SIG: [u8; 4] = *b"APIC";

/// Maximum number of CPUs we track.
const MAX_CPUS: usize = 8;

/// Discovered CPU info.
pub struct CpuTopology {
    pub cpu_count: u32,
    pub apic_ids: [u8; MAX_CPUS],
}

static mut TOPOLOGY: CpuTopology = CpuTopology {
    cpu_count: 0,
    apic_ids: [0; MAX_CPUS],
};

/// Scan BIOS memory for RSDP, parse RSDT → MADT → CPU entries.
/// Returns the number of CPUs found, or 1 if ACPI is unavailable.
pub unsafe fn detect_cpus() -> u32 {
    // Scan for RSDP in BIOS area: 0xE0000 - 0xFFFFF (16-byte aligned)
    let mut rsdp_addr: u64 = 0;
    let mut addr = 0xE0000u64;
    while addr < 0x100000 {
        let ptr = addr as *const [u8; 8];
        if *ptr == RSDP_SIG {
            // Verify checksum (first 20 bytes)
            let mut sum: u8 = 0;
            for i in 0..20 {
                sum = sum.wrapping_add(*((addr + i) as *const u8));
            }
            if sum == 0 {
                rsdp_addr = addr;
                break;
            }
        }
        addr += 16;
    }

    if rsdp_addr == 0 {
        serial::puts(b"       ACPI: RSDP not found\n");
        TOPOLOGY.cpu_count = 1;
        return 1;
    }

    // RSDP: revision at offset 15, RSDT address at offset 16 (4 bytes)
    let rsdt_phys = *((rsdp_addr + 16) as *const u32) as u64;
    if rsdt_phys == 0 {
        serial::puts(b"       ACPI: RSDT address is 0\n");
        TOPOLOGY.cpu_count = 1;
        return 1;
    }

    // Parse RSDT — find MADT
    let rsdt_len = *((rsdt_phys + 4) as *const u32) as usize;
    let entry_count = (rsdt_len - 36) / 4; // 36-byte header, 4-byte entries

    let mut madt_addr: u64 = 0;
    for i in 0..entry_count {
        let entry_phys = *((rsdt_phys + 36 + (i as u64) * 4) as *const u32) as u64;
        if entry_phys == 0 { continue; }
        let sig = entry_phys as *const [u8; 4];
        if *sig == MADT_SIG {
            madt_addr = entry_phys;
            break;
        }
    }

    if madt_addr == 0 {
        serial::puts(b"       ACPI: MADT not found\n");
        TOPOLOGY.cpu_count = 1;
        return 1;
    }

    // Parse MADT — extract Local APIC entries (type 0)
    let madt_len = *((madt_addr + 4) as *const u32) as usize;
    let mut offset = 44usize; // MADT header is 44 bytes
    let mut count = 0u32;

    while offset + 2 <= madt_len {
        let entry_type = *((madt_addr + offset as u64) as *const u8);
        let entry_len = *((madt_addr + offset as u64 + 1) as *const u8) as usize;
        if entry_len == 0 { break; }

        if entry_type == 0 && entry_len >= 8 {
            // Local APIC entry: type(1) + len(1) + acpi_processor_id(1) +
            // apic_id(1) + flags(4)
            let apic_id = *((madt_addr + offset as u64 + 3) as *const u8);
            let flags = *((madt_addr + offset as u64 + 4) as *const u32);
            // Bit 0 = enabled, bit 1 = online capable
            if (flags & 0x3) != 0 && (count as usize) < MAX_CPUS {
                TOPOLOGY.apic_ids[count as usize] = apic_id;
                count += 1;
            }
        }

        offset += entry_len;
    }

    if count == 0 { count = 1; }
    TOPOLOGY.cpu_count = count;

    let mut buf = [0u8; 32];
    let mut pos = 0;
    for &b in b"       ACPI: " { buf[pos] = b; pos += 1; }
    pos += fmt_u32(&mut buf[pos..], count);
    for &b in b" CPUs found\n" { buf[pos] = b; pos += 1; }
    serial::puts(&buf[..pos]);

    count
}

/// Get the discovered CPU topology.
pub fn topology() -> &'static CpuTopology {
    unsafe { &TOPOLOGY }
}

fn fmt_u32(buf: &mut [u8], mut val: u32) -> usize {
    if val == 0 { buf[0] = b'0'; return 1; }
    let mut tmp = [0u8; 10];
    let mut len = 0;
    while val > 0 { tmp[len] = b'0' + (val % 10) as u8; val /= 10; len += 1; }
    for i in 0..len { buf[i] = tmp[len - 1 - i]; }
    len
}
