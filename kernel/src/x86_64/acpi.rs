#![allow(unsafe_op_in_unsafe_fn)]
// kernel/x86_64/acpi.rs — Minimal ACPI parser for CPU topology.
//
// Finds RSDP (from a boot-protocol hint when available, otherwise by
// scanning the legacy BIOS area), walks RSDT/XSDT → MADT, and
// extracts Local APIC entries to discover CPU count and APIC IDs.

use alloc::vec::Vec;

use crate::once::InitOnce;
use crate::serial;
use crate::mm;

/// RSDP physical address supplied by the boot loader (Limine, PVH),
/// populated by `set_rsdp()` before `detect_cpus()` runs. 0 means
/// "fall back to scanning 0xE0000–0xFFFFF". UEFI firmware (GCE's OVMF
/// path) doesn't put the RSDP in that legacy range, so on those
/// platforms the boot-loader hint is the only way to find it.
static BOOT_RSDP_PADDR: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

pub fn set_rsdp(paddr: u64) {
    BOOT_RSDP_PADDR.store(paddr, core::sync::atomic::Ordering::Relaxed);
}

/// ACPI RSDP signature: "RSD PTR "
const RSDP_SIG: [u8; 8] = *b"RSD PTR ";

/// MADT signature: "APIC"
const MADT_SIG: [u8; 4] = *b"APIC";

/// MCFG signature: PCIe Memory-Mapped Configuration table.
const MCFG_SIG: [u8; 4] = *b"MCFG";

/// Sanity cap on any ACPI table length. Real firmware tables are well
/// under a page; anything larger means the length field is corrupted
/// (or, on a hostile hypervisor, crafted). We refuse to walk past this.
const MAX_TABLE_LEN: usize = 64 * 1024;

/// ACPI SDT header size (4-byte sig, 4-byte len, ...).
const SDT_HEADER_LEN: usize = 36;

/// MADT-specific header: SDT + LAPIC address (4) + flags (4).
const MADT_HEADER_LEN: usize = 44;

/// Discovered CPU info. `apic_ids` is heap-backed and grows with the
/// firmware-reported CPU count, so we don't need a compile-time cap.
pub struct CpuTopology {
    pub cpu_count: u32,
    pub apic_ids: Vec<u8>,
}

/// Parsed ACPI topology, populated exactly once on the BSP via
/// `detect_cpus()` before any AP starts.
static TOPOLOGY: InitOnce<CpuTopology> = InitOnce::new();

/// Read a `T` from physical address `phys`, going through the HHDM
/// mapping. Needed because the higher-half Limine kernel has no
/// identity map for low physical memory — a naked `*(phys as *const T)`
/// would fault. On flat-identity boot paths (multiboot2/PVH) this is
/// a no-op (HHDM offset is 0).
///
/// SAFETY: `phys` must point to a valid, readable `T`.
unsafe fn read_phys<T: Copy>(phys: u64) -> T {
    *(mm::phys_to_virt(phys) as *const T)
}

/// Scan the legacy BIOS area (0xE0000–0xFFFFF) for the RSDP signature.
/// Returns the physical address, or 0 if not present. Only meaningful
/// under SeaBIOS-style legacy firmware; UEFI (e.g. GCE's OVMF) does
/// NOT put the RSDP here, which is why we prefer the boot-protocol
/// hint in `detect_cpus` and only fall back to this as a last resort.
///
/// SAFETY: reads arbitrary low physical memory via phys_to_virt.
unsafe fn find_rsdp_bios_scan() -> u64 {
    let mut addr = 0xE0000u64;
    while addr < 0x100000 {
        let sig: [u8; 8] = read_phys(addr);
        if sig == RSDP_SIG {
            let mut sum: u8 = 0;
            for i in 0..20 {
                sum = sum.wrapping_add(read_phys::<u8>(addr + i));
            }
            if sum == 0 {
                return addr;
            }
        }
        addr += 16;
    }
    0
}

/// Walk an RSDT (entry_size=4) or XSDT (entry_size=8) at `sdt_phys`
/// and return the physical address of the first table whose 4-byte
/// signature matches `sig`, or 0 if absent or the length field is
/// obviously bogus.
unsafe fn find_table(sdt_phys: u64, entry_size: u64, sig: [u8; 4]) -> u64 {
    let sdt_len: u32 = read_phys(sdt_phys + 4);
    let sdt_len = sdt_len as usize;
    if sdt_len < SDT_HEADER_LEN || sdt_len > MAX_TABLE_LEN {
        return 0;
    }
    let entry_count = (sdt_len - SDT_HEADER_LEN) as u64 / entry_size;

    for i in 0..entry_count {
        let entry_phys_addr = sdt_phys + SDT_HEADER_LEN as u64 + i * entry_size;
        let entry_phys: u64 = if entry_size == 8 {
            read_phys::<u64>(entry_phys_addr)
        } else {
            read_phys::<u32>(entry_phys_addr) as u64
        };
        if entry_phys == 0 { continue; }
        let entry_sig: [u8; 4] = read_phys(entry_phys);
        if entry_sig == sig {
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
    let raw_len: u32 = read_phys(madt_addr + 4);
    let raw_len = raw_len as usize;
    // Cap at MAX_TABLE_LEN so a corrupt length can't drag us off the end
    // of physical memory. raw_len < header is an unusable table.
    if raw_len < MADT_HEADER_LEN {
        return 0;
    }
    let madt_len = core::cmp::min(raw_len, MAX_TABLE_LEN);
    let mut offset = MADT_HEADER_LEN;
    let mut count = 0u32;

    while offset + 2 <= madt_len {
        let entry_type: u8 = read_phys(madt_addr + offset as u64);
        let entry_len = read_phys::<u8>(madt_addr + offset as u64 + 1) as usize;
        // Malformed entry: zero-length would loop forever; oversize would
        // skip past the end of the table into unrelated memory.
        if entry_len < 2 || offset + entry_len > madt_len {
            break;
        }

        if entry_type == 0 && entry_len >= 8 {
            // Local APIC entry: type(1) + len(1) + acpi_processor_id(1) +
            // apic_id(1) + flags(4). Bit 0 = enabled, bit 1 = online capable.
            let apic_id: u8 = read_phys(madt_addr + offset as u64 + 3);
            let flags: u32 = read_phys(madt_addr + offset as u64 + 4);
            if (flags & 0x3) != 0 {
                topo.apic_ids.push(apic_id);
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

/// Locate the system root SDT (XSDT preferred on ACPI ≥ 2.0, RSDT on
/// 1.0). Returns `(sdt_phys, entry_size_bytes)` where `entry_size` is
/// 8 for XSDT and 4 for RSDT, or 0 / 0 if no RSDP was supplied.
///
/// SAFETY: dereferences boot-protocol or scan-derived physical
/// addresses; caller relies on those being valid ACPI structures.
unsafe fn locate_root_sdt() -> (u64, u64) {
    // Prefer the boot-protocol RSDP hint; only fall back to the BIOS
    // scan when no loader told us where to look. UEFI firmware (GCE's
    // OVMF path) doesn't put the RSDP in 0xE0000–0xFFFFF, so the scan
    // fails there.
    let rsdp_addr = BOOT_RSDP_PADDR.load(core::sync::atomic::Ordering::Relaxed);
    let rsdp_addr = if rsdp_addr != 0 { rsdp_addr } else { find_rsdp_bios_scan() };
    if rsdp_addr == 0 {
        return (0, 0);
    }

    // ACPI 1.0 RSDP carries a 32-bit RSDT pointer at offset 16.
    // ACPI 2.0+ (revision >= 2) adds an 8-byte XSDT pointer at offset
    // 24 with 64-bit entries. Modern firmware — and every UEFI path —
    // reports rev=2, and may leave the old RSDT pointer 0.
    let revision: u8 = read_phys(rsdp_addr + 15);
    if revision >= 2 {
        let xsdt: u64 = read_phys(rsdp_addr + 24);
        if xsdt != 0 {
            return (xsdt, 8);
        }
    }
    (read_phys::<u32>(rsdp_addr + 16) as u64, 4)
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
        apic_ids: Vec::new(),
    };

    let (sdt_phys, entry_size) = locate_root_sdt();
    if sdt_phys == 0 {
        return finish(topo, b"       ACPI: RSDP not found\n");
    }

    let madt_addr = find_table(sdt_phys, entry_size, MADT_SIG);
    if madt_addr == 0 {
        return finish(topo, b"       ACPI: MADT not found\n");
    }

    let mut count = parse_madt_entries(madt_addr, &mut topo);
    if count == 0 { count = 1; }
    topo.cpu_count = count;
    TOPOLOGY.init(topo);
    // CPU count is already surfaced in the boot banner's `cpu:` line;
    // the per-table-source provenance isn't actionable.
    count
}

/// Get the discovered CPU topology. Panics if `detect_cpus` hasn't run.
pub fn topology() -> &'static CpuTopology {
    TOPOLOGY.get()
}

/// Locate the ECAM (PCIe Memory-Mapped Configuration) base address for
/// PCI segment 0, bus 0 via the ACPI MCFG table. Returns `None` if no
/// RSDP was supplied, MCFG isn't present (legacy `pc`/`i440fx` machine
/// types don't expose it), or its layout is invalid — caller falls back
/// to the legacy 0xCF8/0xCFC port-I/O config mechanism in that case.
///
/// MCFG layout (PCI Firmware Spec 3.0 §4.1.2):
///   +0   ACPI std header (36 bytes)
///   +36  reserved (8 bytes)
///   +44  array of "Configuration Space Base Address Allocation"
///        entries, each 16 bytes:
///          u64 base_address
///          u16 pci_segment_group
///          u8  start_bus_number
///          u8  end_bus_number
///          u32 reserved
///
/// We pick the first entry covering segment 0, bus 0 — on QEMU q35
/// and GCE there is exactly one.
pub unsafe fn mcfg_ecam_base() -> Option<u64> {
    let (sdt_phys, entry_size) = locate_root_sdt();
    if sdt_phys == 0 { return None; }

    let mcfg = find_table(sdt_phys, entry_size, MCFG_SIG);
    if mcfg == 0 { return None; }

    let total_len: u32 = read_phys(mcfg + 4);
    let total_len = total_len as usize;
    // Header (36) + reserved (8) + at least one 16-byte allocation.
    if total_len < 60 || total_len > MAX_TABLE_LEN { return None; }

    let entries_off = (SDT_HEADER_LEN + 8) as u64;
    let entry_count = (total_len - SDT_HEADER_LEN - 8) / 16;
    for i in 0..entry_count as u64 {
        let base = mcfg + entries_off + i * 16;
        let segment: u16 = read_phys(base + 8);
        let start_bus: u8 = read_phys(base + 10);
        if segment == 0 && start_bus == 0 {
            let phys: u64 = read_phys(base);
            if phys != 0 { return Some(phys); }
        }
    }
    None
}

