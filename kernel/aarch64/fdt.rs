// kernel/fdt.rs — Minimal FDT (Device Tree Blob) scanner for ARM64
//
// Walks the DTB structure block looking for nodes with specific compatible
// strings and extracts their MMIO base addresses from the reg property.
//
// Assumptions (standard for QEMU virt and Apple VZ):
//   - #address-cells = 2, #size-cells = 2 at root level
//   - reg addresses stored as (hi32 BE, lo32 BE) -> 64-bit address
//   - Devices of interest are direct children of root (depth 1) or /soc
//
// On x86_64 this module provides no-op stubs.

use crate::once::InitOnce;

// ============================================================================
// FDT Info struct — device tree discovery results
// ============================================================================

/// Device information discovered by parsing the FDT during boot.
#[repr(C)]
pub struct FdtInfo {
    pub uart_base: u64,
    pub virtio_bases: [u64; 32],
    pub virtio_irqs: [u32; 32],
    pub virtio_count: i32,
    pub gic_dist_base: u64,
    pub gic_redist_base: u64,
    pub gic_version: u8,
    pub pcie_ecam_base: u64,
    pub pcie_ecam_size: u64,
    pub ram_base: u64,
    pub ram_size: u64,
    pub pci_mmio32_base: u64,
    pub pci_mmio32_size: u64,
    pub pci_irqs: [u32; 8],
    pub cpu_count: u32,
}

impl FdtInfo {
    const ZEROED: FdtInfo = FdtInfo {
        uart_base: 0,
        virtio_bases: [0; 32],
        virtio_irqs: [0; 32],
        virtio_count: 0,
        gic_dist_base: 0,
        gic_redist_base: 0,
        gic_version: 0,
        pcie_ecam_base: 0,
        pcie_ecam_size: 0,
        ram_base: 0,
        ram_size: 0,
        pci_mmio32_base: 0,
        pci_mmio32_size: 0,
        pci_irqs: [0; 8],
        cpu_count: 0,
    };
}

/// Parsed FDT, populated exactly once by `init()` before any AP starts.
static G_INFO: InitOnce<FdtInfo> = InitOnce::new();

// ============================================================================
// Big-endian helpers (safe, slice-based)
// ============================================================================

#[inline]
fn be32(s: &[u8]) -> u32 {
    ((s[0] as u32) << 24) | ((s[1] as u32) << 16) | ((s[2] as u32) << 8) | (s[3] as u32)
}

#[inline]
fn be64_2cell(s: &[u8]) -> u64 {
    ((be32(s) as u64) << 32) | be32(&s[4..]) as u64
}

// ============================================================================
// String helpers (safe, slice-based)
// ============================================================================

/// Check if the null-terminated string at `s` equals `name`.
/// `s` must start at the string and extend at least to the null terminator.
fn str_at_eq(s: &[u8], name: &[u8]) -> bool {
    if s.len() < name.len() + 1 {
        return false;
    }
    s[..name.len()] == *name && s[name.len()] == 0
}

/// Check if the null-string list `data` contains `needle`.
fn strlist_has(data: &[u8], needle: &[u8]) -> bool {
    let mut start = 0;
    while start < data.len() {
        // Find the end of the current null-terminated string
        let mut end = start;
        while end < data.len() && data[end] != 0 {
            end += 1;
        }
        let s = &data[start..end];
        if s == needle {
            return true;
        }
        // Skip the null terminator
        start = end + 1;
    }
    false
}

// ============================================================================
// DTB structure tokens
// ============================================================================

const FDT_MAGIC: u32 = 0xD00DFEED;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

// Compatible flags
const CF_PL011: u32 = 1 << 0;
const CF_VIRTIO: u32 = 1 << 1;
const CF_GICV2: u32 = 1 << 2;
const CF_PCI: u32 = 1 << 3;
const CF_MEMORY: u32 = 1 << 4;
const CF_GICV3: u32 = 1 << 5;

// ============================================================================
// Per-node state during parsing
// ============================================================================

const MAX_DEPTH: usize = 8;

struct NodeState {
    compat: u32,
    reg: u64,
    reg_size: u64,
    has_reg: bool,
    reg2: u64,
    has_reg2: bool,
    /// Offset into the DTB slice where the ranges property value begins.
    ranges_off: usize,
    ranges_len: u32,
    has_ranges: bool,
    irq: u32,
    has_irq: bool,
    /// Offset into the DTB slice where the interrupt-map property value begins.
    int_map_off: usize,
    int_map_len: u32,
    has_int_map: bool,
}

impl NodeState {
    const fn new() -> Self {
        NodeState {
            compat: 0,
            reg: 0,
            reg_size: 0,
            has_reg: false,
            reg2: 0,
            has_reg2: false,
            ranges_off: 0,
            ranges_len: 0,
            has_ranges: false,
            irq: 0,
            has_irq: false,
            int_map_off: 0,
            int_map_len: 0,
            has_int_map: false,
        }
    }
}

// ============================================================================
// Main parser
// ============================================================================

#[cfg(target_arch = "aarch64")]
fn parse_dtb(dtb: &[u8]) -> Option<FdtInfo> {
    if dtb.len() < 40 {
        return None;
    }

    if be32(dtb) != FDT_MAGIC {
        return None;
    }

    let off_struct = be32(&dtb[8..]) as usize;
    let off_strings = be32(&dtb[12..]) as usize;

    let mut pos = off_struct;

    let mut stack = [const { NodeState::new() }; MAX_DEPTH];
    let mut depth: i32 = 0;
    // Build the parsed result in a local — published once at the end via
    // InitOnce so every cross-core read sees a fully-initialised struct.
    let mut info = FdtInfo::ZEROED;

    loop {
        if pos + 4 > dtb.len() {
            return None;
        }
        let tok = be32(&dtb[pos..]);
        pos += 4;

        match tok {
            FDT_BEGIN_NODE => {
                if (depth as usize) < MAX_DEPTH {
                    stack[depth as usize] = NodeState::new();
                }
                depth += 1;
                // Read node name, then skip
                let name_start = pos;
                while pos < dtb.len() && dtb[pos] != 0 {
                    pos += 1;
                }
                let name = &dtb[name_start..pos];
                pos += 1; // skip null
                pos = (pos + 3) & !3; // align

                // Count cpu@N nodes (children of /cpus)
                if name.len() >= 4 && name[0] == b'c' && name[1] == b'p'
                    && name[2] == b'u' && name[3] == b'@'
                {
                    info.cpu_count += 1;
                }
            }

            FDT_END_NODE => {
                depth -= 1;
                if depth >= 0 && (depth as usize) < MAX_DEPTH {
                    let ns = &stack[depth as usize];
                    if ns.has_reg {
                        if (ns.compat & CF_PL011) != 0 && info.uart_base == 0 {
                            info.uart_base = ns.reg;
                        }

                        if (ns.compat & CF_VIRTIO) != 0 && info.virtio_count < 32 {
                            let idx = info.virtio_count as usize;
                            info.virtio_bases[idx] = ns.reg;
                            info.virtio_irqs[idx] = if ns.has_irq { ns.irq } else { 0 };
                            info.virtio_count += 1;
                        }

                        if (ns.compat & CF_GICV2) != 0 && info.gic_dist_base == 0 {
                            info.gic_dist_base = ns.reg;
                            info.gic_version = 2;
                        }

                        if (ns.compat & CF_GICV3) != 0 && info.gic_dist_base == 0 {
                            info.gic_dist_base = ns.reg;
                            info.gic_redist_base =
                                if ns.has_reg2 { ns.reg2 } else { 0 };
                            info.gic_version = 3;
                        }

                        if (ns.compat & CF_PCI) != 0 && info.pcie_ecam_base == 0 {
                            info.pcie_ecam_base = ns.reg;
                            info.pcie_ecam_size = ns.reg_size;
                        }

                        // Parse PCI "ranges" for 32-bit MMIO aperture
                        if (ns.compat & CF_PCI) != 0
                            && ns.has_ranges
                            && ns.ranges_len >= 28
                            && info.pci_mmio32_base == 0
                        {
                            let ranges = &dtb[ns.ranges_off..];
                            let mut off: u32 = 0;
                            while off + 28 <= ns.ranges_len {
                                let o = off as usize;
                                let flags = be32(&ranges[o..]);
                                let space = (flags >> 24) & 3;
                                if space == 2 {
                                    // 32-bit memory space
                                    let cpu_hi = be32(&ranges[o + 12..]) as u64;
                                    let cpu_lo = be32(&ranges[o + 16..]) as u64;
                                    info.pci_mmio32_base = (cpu_hi << 32) | cpu_lo;
                                    info.pci_mmio32_size =
                                        ((be32(&ranges[o + 20..]) as u64) << 32)
                                            | be32(&ranges[o + 24..]) as u64;
                                    break;
                                }
                                off += 28;
                            }
                        }

                        // Parse PCI interrupt-map
                        if (ns.compat & CF_PCI) != 0
                            && ns.has_int_map
                            && ns.int_map_len >= 40
                        {
                            let imap = &dtb[ns.int_map_off..];
                            let mut off: u32 = 0;
                            while off + 40 <= ns.int_map_len {
                                let o = off as usize;
                                let child_hi = be32(&imap[o..]);
                                let gic_type = be32(&imap[o + 28..]);
                                let gic_irq = be32(&imap[o + 32..]);
                                let slot = (child_hi >> 11) & 0x1F;
                                let intid = if gic_type == 0 {
                                    gic_irq + 32
                                } else {
                                    gic_irq + 16
                                };
                                if slot < 8 && info.pci_irqs[slot as usize] == 0 {
                                    info.pci_irqs[slot as usize] = intid;
                                }
                                off += 40;
                            }
                        }

                        if (ns.compat & CF_MEMORY) != 0 && info.ram_size == 0 {
                            info.ram_base = ns.reg;
                            info.ram_size = ns.reg_size;
                        }
                    }
                }
            }

            FDT_PROP => {
                if pos + 8 > dtb.len() {
                    return None;
                }
                let vlen = be32(&dtb[pos..]);
                pos += 4;
                let nameoff = be32(&dtb[pos..]);
                pos += 4;
                let vdata_off = pos;
                // Advance past value (padded to 4-byte alignment)
                pos += ((vlen + 3) & !3) as usize;

                let d = depth - 1;
                if d >= 0 && (d as usize) < MAX_DEPTH {
                    let ns = &mut stack[d as usize];
                    let pname_off = off_strings + nameoff as usize;
                    let pname = &dtb[pname_off..];

                    if str_at_eq(pname, b"compatible") {
                        let vdata = &dtb[vdata_off..vdata_off + vlen as usize];
                        if strlist_has(vdata, b"arm,pl011") {
                            ns.compat |= CF_PL011;
                        }
                        if strlist_has(vdata, b"virtio,mmio") {
                            ns.compat |= CF_VIRTIO;
                        }
                        if strlist_has(vdata, b"arm,gic-400")
                            || strlist_has(vdata, b"arm,cortex-a15-gic")
                        {
                            ns.compat |= CF_GICV2;
                        }
                        if strlist_has(vdata, b"pci-host-ecam-generic") {
                            ns.compat |= CF_PCI;
                        }
                        if strlist_has(vdata, b"arm,gic-v3") {
                            ns.compat |= CF_GICV3;
                        }
                    } else if str_at_eq(pname, b"device_type") {
                        let vdata = &dtb[vdata_off..vdata_off + vlen as usize];
                        if strlist_has(vdata, b"pci") {
                            ns.compat |= CF_PCI;
                        }
                        if strlist_has(vdata, b"memory") {
                            ns.compat |= CF_MEMORY;
                        }
                    } else if str_at_eq(pname, b"reg") && vlen >= 8 && !ns.has_reg {
                        let vdata = &dtb[vdata_off..];
                        ns.reg = be64_2cell(vdata);
                        ns.reg_size = if vlen >= 16 {
                            be64_2cell(&vdata[8..])
                        } else {
                            0
                        };
                        ns.has_reg = true;
                        if vlen >= 32 {
                            ns.reg2 = be64_2cell(&vdata[16..]);
                            ns.has_reg2 = true;
                        }
                    } else if str_at_eq(pname, b"ranges") && vlen > 0 {
                        ns.ranges_off = vdata_off;
                        ns.ranges_len = vlen;
                        ns.has_ranges = true;
                    } else if str_at_eq(pname, b"interrupt-map") {
                        ns.int_map_off = vdata_off;
                        ns.int_map_len = vlen;
                        ns.has_int_map = true;
                    } else if str_at_eq(pname, b"interrupts") && vlen >= 12 && !ns.has_irq {
                        let vdata = &dtb[vdata_off..];
                        let irq_type = be32(vdata);
                        let irq_num = be32(&vdata[4..]);
                        ns.irq = if irq_type == 0 {
                            irq_num + 32
                        } else {
                            irq_num + 16
                        };
                        ns.has_irq = true;
                    }
                }
            }

            FDT_NOP => {}

            FDT_END => return Some(info),

            _ => return None, // corrupted DTB
        }
    }
}

// ============================================================================
// Public Rust API — for Rust crate consumers (serial_rs, drivers_rs, etc.)
// ============================================================================

/// Return a reference to the global parsed FDT info. Panics if `init`
/// has not been called yet (which would indicate a boot ordering bug).
pub fn info() -> &'static FdtInfo {
    G_INFO.get()
}

// ============================================================================
// Public API
// ============================================================================

/// Parse the DTB at the given physical address.
/// Safe to call with dtb_addr=0 (publishes a zeroed FdtInfo so later
/// `info()` calls don't panic; nothing useful will be discovered).
/// Must be called exactly once during boot, single-threaded, before any
/// other code calls `info()`.
pub fn init(dtb_addr: u64) {
    #[cfg(target_arch = "aarch64")]
    {
        if dtb_addr == 0 {
            G_INFO.init(FdtInfo::ZEROED);
            return;
        }
        // Safety: On bare-metal aarch64, the DTB physical address is identity-mapped
        // (or HHDM-mapped) and valid for the entire DTB. We read total_size from
        // the header (offset 4) to determine the slice length. After this single
        // unsafe slice creation, all parsing is done with safe slice operations.
        let total_size = unsafe {
            let p = dtb_addr as *const u8;
            be32(core::slice::from_raw_parts(p.add(4), 4))
        } as usize;
        if total_size < 40 {
            G_INFO.init(FdtInfo::ZEROED);
            return;
        }
        let dtb =
            unsafe { core::slice::from_raw_parts(dtb_addr as *const u8, total_size) };
        let parsed = parse_dtb(dtb).unwrap_or(FdtInfo::ZEROED);
        G_INFO.init(parsed);
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = dtb_addr;
    }
}

/// Return a pointer to the parsed FDT info. Used by code that needs a
/// raw pointer (e.g., FFI). Panics if `init` has not been called.
pub fn info_ptr() -> *const FdtInfo {
    G_INFO.get() as *const FdtInfo
}
