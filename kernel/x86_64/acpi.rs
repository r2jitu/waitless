#![allow(unsafe_op_in_unsafe_fn)]
// kernel/x86_64/acpi.rs — Minimal ACPI parser for CPU topology.
//
// Finds RSDP in BIOS memory, parses RSDT, finds MADT, extracts
// Local APIC entries to discover CPU count and APIC IDs.

use crate::once::InitOnce;
use crate::serial;

/// ACPI RSDP signature: "RSD PTR "
const RSDP_SIG: [u8; 8] = *b"RSD PTR ";

/// MADT signature: "APIC"
const MADT_SIG: [u8; 4] = *b"APIC";

/// Maximum number of CPUs we track.
const MAX_CPUS: usize = 8;

/// Sanity cap on any ACPI table length. Real firmware tables are well
/// under a page; anything larger means the length field is corrupted
/// (or, on a hostile hypervisor, crafted). We refuse to walk past this.
const MAX_TABLE_LEN: usize = 64 * 1024;

/// ACPI SDT header size (4-byte sig, 4-byte len, ...).
const SDT_HEADER_LEN: usize = 36;

/// MADT-specific header: SDT + LAPIC address (4) + flags (4).
const MADT_HEADER_LEN: usize = 44;

/// Discovered CPU info.
pub struct CpuTopology {
    pub cpu_count: u32,
    pub apic_ids: [u8; MAX_CPUS],
}

/// Parsed ACPI topology, populated exactly once on the BSP via
/// `detect_cpus()` before any AP starts.
static TOPOLOGY: InitOnce<CpuTopology> = InitOnce::new();

/// Scan the BIOS area (0xE0000–0xFFFFF) for the RSDP signature, verify the
/// 20-byte checksum, and return its physical address. Returns 0 if not found.
///
/// SAFETY: dereferences raw pointers to BIOS memory; only safe to call on
/// x86_64 with identity-mapped low memory available.
unsafe fn find_rsdp() -> u64 {
    let mut addr = 0xE0000u64;
    while addr < 0x100000 {
        let ptr = addr as *const [u8; 8];
        if *ptr == RSDP_SIG {
            let mut sum: u8 = 0;
            for i in 0..20 {
                sum = sum.wrapping_add(*((addr + i) as *const u8));
            }
            if sum == 0 {
                return addr;
            }
        }
        addr += 16;
    }
    0
}

/// Walk the RSDT pointed to by `rsdt_phys` and return the physical address
/// of the first MADT (signature "APIC"). Returns 0 if not found or if the
/// RSDT length field is obviously bogus.
///
/// SAFETY: caller must ensure `rsdt_phys` points to a valid RSDT.
unsafe fn find_madt(rsdt_phys: u64) -> u64 {
    let rsdt_len = *((rsdt_phys + 4) as *const u32) as usize;
    if rsdt_len < SDT_HEADER_LEN || rsdt_len > MAX_TABLE_LEN {
        return 0;
    }
    let entry_count = (rsdt_len - SDT_HEADER_LEN) / 4;

    for i in 0..entry_count {
        let entry_phys = *((rsdt_phys + SDT_HEADER_LEN as u64 + (i as u64) * 4)
            as *const u32) as u64;
        if entry_phys == 0 { continue; }
        let sig = entry_phys as *const [u8; 4];
        if *sig == MADT_SIG {
            return entry_phys;
        }
    }
    0
}

/// Walk the Local APIC entries (type 0) in the MADT at `madt_addr` and
/// populate `topo.apic_ids`. Returns the number of enabled APICs found.
///
/// SAFETY: caller must ensure `madt_addr` points to a valid MADT.
unsafe fn parse_madt_entries(madt_addr: u64, topo: &mut CpuTopology) -> u32 {
    let raw_len = *((madt_addr + 4) as *const u32) as usize;
    // Cap at MAX_TABLE_LEN so a corrupt length can't drag us off the end
    // of physical memory. raw_len < header is an unusable table.
    if raw_len < MADT_HEADER_LEN {
        return 0;
    }
    let madt_len = core::cmp::min(raw_len, MAX_TABLE_LEN);
    let mut offset = MADT_HEADER_LEN;
    let mut count = 0u32;

    while offset + 2 <= madt_len {
        let entry_type = *((madt_addr + offset as u64) as *const u8);
        let entry_len = *((madt_addr + offset as u64 + 1) as *const u8) as usize;
        // Malformed entry: zero-length would loop forever; oversize would
        // skip past the end of the table into unrelated memory.
        if entry_len < 2 || offset + entry_len > madt_len {
            break;
        }

        if entry_type == 0 && entry_len >= 8 {
            // Local APIC entry: type(1) + len(1) + acpi_processor_id(1) +
            // apic_id(1) + flags(4). Bit 0 = enabled, bit 1 = online capable.
            let apic_id = *((madt_addr + offset as u64 + 3) as *const u8);
            let flags = *((madt_addr + offset as u64 + 4) as *const u32);
            if (flags & 0x3) != 0 && (count as usize) < MAX_CPUS {
                topo.apic_ids[count as usize] = apic_id;
                count += 1;
            }
        }

        offset += entry_len;
    }

    count
}

/// Cache the topology and return its CPU count, logging a one-line message.
fn finish(topo: CpuTopology, msg: &[u8]) -> u32 {
    let count = topo.cpu_count;
    TOPOLOGY.init(topo);
    serial::puts(msg);
    count
}

/// Scan BIOS memory for RSDP, parse RSDT → MADT → CPU entries.
/// Returns the number of CPUs found, or 1 if ACPI is unavailable.
///
/// Idempotent: subsequent calls return the cached topology rather than
/// re-parsing (and rather than panicking on InitOnce double-init). The
/// virtio_net driver and boot/entry both call this; the first wins,
/// the rest read the cached value.
pub unsafe fn detect_cpus() -> u32 {
    if let Some(t) = TOPOLOGY.try_get() {
        return t.cpu_count;
    }
    let mut topo = CpuTopology {
        cpu_count: 1,
        apic_ids: [0; MAX_CPUS],
    };

    let rsdp_addr = find_rsdp();
    if rsdp_addr == 0 {
        return finish(topo, b"       ACPI: RSDP not found\n");
    }

    // RSDP: RSDT address at offset 16 (4 bytes).
    let rsdt_phys = *((rsdp_addr + 16) as *const u32) as u64;
    if rsdt_phys == 0 {
        return finish(topo, b"       ACPI: RSDT address is 0\n");
    }

    let madt_addr = find_madt(rsdt_phys);
    if madt_addr == 0 {
        return finish(topo, b"       ACPI: MADT not found\n");
    }

    let mut count = parse_madt_entries(madt_addr, &mut topo);
    if count == 0 { count = 1; }
    topo.cpu_count = count;
    TOPOLOGY.init(topo);

    let mut buf = [0u8; 32];
    let mut pos = 0;
    for &b in b"       ACPI: " { buf[pos] = b; pos += 1; }
    pos += fmt_u32(&mut buf[pos..], count);
    for &b in b" CPUs found\n" { buf[pos] = b; pos += 1; }
    serial::puts(&buf[..pos]);

    count
}

/// Get the discovered CPU topology. Panics if `detect_cpus` hasn't run.
pub fn topology() -> &'static CpuTopology {
    TOPOLOGY.get()
}

fn fmt_u32(buf: &mut [u8], mut val: u32) -> usize {
    if val == 0 { buf[0] = b'0'; return 1; }
    let mut tmp = [0u8; 10];
    let mut len = 0;
    while val > 0 { tmp[len] = b'0' + (val % 10) as u8; val /= 10; len += 1; }
    for i in 0..len { buf[i] = tmp[len - 1 - i]; }
    len
}
