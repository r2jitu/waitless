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

use core::ptr;

// ============================================================================
// FDT Info struct — shared with C++ callers and Rust crates
// ============================================================================

/// Device information discovered from the FDT.
/// Layout must match kernel/aarch64/fdt.h fdt::Info exactly.
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
}

static mut G_INFO: FdtInfo = FdtInfo {
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
};

// ============================================================================
// Big-endian helpers
// ============================================================================

#[inline]
fn be32(p: *const u8) -> u32 {
    unsafe {
        ((*p.add(0) as u32) << 24)
            | ((*p.add(1) as u32) << 16)
            | ((*p.add(2) as u32) << 8)
            | (*p.add(3) as u32)
    }
}

#[inline]
fn be64_2cell(p: *const u8) -> u64 {
    ((be32(p) as u64) << 32) | be32(unsafe { p.add(4) }) as u64
}

// ============================================================================
// String helpers
// ============================================================================

fn str_eq(a: *const u8, b: &[u8]) -> bool {
    let mut i = 0;
    unsafe {
        while i < b.len() {
            if *a.add(i) != b[i] {
                return false;
            }
            i += 1;
        }
        // a must also be null-terminated here
        *a.add(i) == 0
    }
}

/// Check if the null-string list [data, data+len) contains needle.
fn strlist_has(data: *const u8, len: u32, needle: &[u8]) -> bool {
    let end = unsafe { data.add(len as usize) };
    let mut p = data;
    while (p as usize) < (end as usize) {
        // Check if current string matches needle
        let mut matches = true;
        let mut i = 0;
        let start = p;
        unsafe {
            while (p as usize) < (end as usize) && *p != 0 {
                if i < needle.len() {
                    if *p != needle[i] {
                        matches = false;
                    }
                }
                i += 1;
                p = p.add(1);
            }
            if matches && i == needle.len() {
                return true;
            }
            // Skip null terminator
            if (p as usize) < (end as usize) {
                p = p.add(1);
            }
        }
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
    ranges_data: *const u8,
    ranges_len: u32,
    irq: u32,
    has_irq: bool,
    int_map_data: *const u8,
    int_map_len: u32,
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
            ranges_data: ptr::null(),
            ranges_len: 0,
            irq: 0,
            has_irq: false,
            int_map_data: ptr::null(),
            int_map_len: 0,
        }
    }
}

// ============================================================================
// Main parser
// ============================================================================

#[cfg(target_arch = "aarch64")]
unsafe fn parse_dtb(dtb_addr: u64) {
    if dtb_addr == 0 {
        return;
    }
    let dtb = dtb_addr as *const u8;

    if be32(dtb) != FDT_MAGIC {
        return;
    }

    let off_struct = be32(dtb.add(8)) as usize;
    let off_strings = be32(dtb.add(12)) as usize;

    let strings = dtb.add(off_strings);
    let mut p = dtb.add(off_struct);

    let mut stack = [const { NodeState::new() }; MAX_DEPTH];
    let mut depth: i32 = 0;

    loop {
        let tok = be32(p);
        p = p.add(4);

        match tok {
            FDT_BEGIN_NODE => {
                if (depth as usize) < MAX_DEPTH {
                    stack[depth as usize] = NodeState::new();
                }
                depth += 1;
                // Skip null-terminated node name
                while *p != 0 {
                    p = p.add(1);
                }
                p = p.add(1); // skip null
                // Align to 4-byte boundary
                p = ((p as usize + 3) & !3) as *const u8;
            }

            FDT_END_NODE => {
                depth -= 1;
                if depth >= 0 && (depth as usize) < MAX_DEPTH {
                    let ns = &stack[depth as usize];
                    if ns.has_reg {
                        if (ns.compat & CF_PL011) != 0 && G_INFO.uart_base == 0 {
                            G_INFO.uart_base = ns.reg;
                        }

                        if (ns.compat & CF_VIRTIO) != 0 && G_INFO.virtio_count < 32 {
                            let idx = G_INFO.virtio_count as usize;
                            G_INFO.virtio_bases[idx] = ns.reg;
                            G_INFO.virtio_irqs[idx] = if ns.has_irq { ns.irq } else { 0 };
                            G_INFO.virtio_count += 1;
                        }

                        if (ns.compat & CF_GICV2) != 0 && G_INFO.gic_dist_base == 0 {
                            G_INFO.gic_dist_base = ns.reg;
                            G_INFO.gic_version = 2;
                        }

                        if (ns.compat & CF_GICV3) != 0 && G_INFO.gic_dist_base == 0 {
                            G_INFO.gic_dist_base = ns.reg;
                            G_INFO.gic_redist_base = if ns.has_reg2 { ns.reg2 } else { 0 };
                            G_INFO.gic_version = 3;
                        }

                        if (ns.compat & CF_PCI) != 0 && G_INFO.pcie_ecam_base == 0 {
                            G_INFO.pcie_ecam_base = ns.reg;
                            G_INFO.pcie_ecam_size = ns.reg_size;
                        }

                        // Parse PCI "ranges" for 32-bit MMIO aperture
                        if (ns.compat & CF_PCI) != 0
                            && !ns.ranges_data.is_null()
                            && ns.ranges_len >= 28
                            && G_INFO.pci_mmio32_base == 0
                        {
                            let mut off: u32 = 0;
                            while off + 28 <= ns.ranges_len {
                                let e = ns.ranges_data.add(off as usize);
                                let flags = be32(e);
                                let space = (flags >> 24) & 3;
                                if space == 2 {
                                    // 32-bit memory space
                                    let cpu_hi = be32(e.add(12)) as u64;
                                    let cpu_lo = be32(e.add(16)) as u64;
                                    G_INFO.pci_mmio32_base = (cpu_hi << 32) | cpu_lo;
                                    G_INFO.pci_mmio32_size =
                                        ((be32(e.add(20)) as u64) << 32) | be32(e.add(24)) as u64;
                                    break;
                                }
                                off += 28;
                            }
                        }

                        // Parse PCI interrupt-map
                        if (ns.compat & CF_PCI) != 0
                            && !ns.int_map_data.is_null()
                            && ns.int_map_len >= 40
                        {
                            let mut off: u32 = 0;
                            while off + 40 <= ns.int_map_len {
                                let e = ns.int_map_data.add(off as usize);
                                let child_hi = be32(e);
                                let gic_type = be32(e.add(28));
                                let gic_irq = be32(e.add(32));
                                let slot = (child_hi >> 11) & 0x1F;
                                let intid = if gic_type == 0 {
                                    gic_irq + 32
                                } else {
                                    gic_irq + 16
                                };
                                if slot < 8 && G_INFO.pci_irqs[slot as usize] == 0 {
                                    G_INFO.pci_irqs[slot as usize] = intid;
                                }
                                off += 40;
                            }
                        }

                        if (ns.compat & CF_MEMORY) != 0 && G_INFO.ram_size == 0 {
                            G_INFO.ram_base = ns.reg;
                            G_INFO.ram_size = ns.reg_size;
                        }
                    }
                }
            }

            FDT_PROP => {
                let vlen = be32(p);
                p = p.add(4);
                let nameoff = be32(p);
                p = p.add(4);
                let vdata = p;
                // Advance past value (padded to 4-byte alignment)
                p = p.add(((vlen + 3) & !3) as usize);

                let d = depth - 1;
                if d >= 0 && (d as usize) < MAX_DEPTH {
                    let ns = &mut stack[d as usize];
                    let pname = strings.add(nameoff as usize);

                    if str_eq(pname, b"compatible") {
                        if strlist_has(vdata, vlen, b"arm,pl011") {
                            ns.compat |= CF_PL011;
                        }
                        if strlist_has(vdata, vlen, b"virtio,mmio") {
                            ns.compat |= CF_VIRTIO;
                        }
                        if strlist_has(vdata, vlen, b"arm,gic-400")
                            || strlist_has(vdata, vlen, b"arm,cortex-a15-gic")
                        {
                            ns.compat |= CF_GICV2;
                        }
                        if strlist_has(vdata, vlen, b"pci-host-ecam-generic") {
                            ns.compat |= CF_PCI;
                        }
                        if strlist_has(vdata, vlen, b"arm,gic-v3") {
                            ns.compat |= CF_GICV3;
                        }
                    } else if str_eq(pname, b"device_type") {
                        if strlist_has(vdata, vlen, b"pci") {
                            ns.compat |= CF_PCI;
                        }
                        if strlist_has(vdata, vlen, b"memory") {
                            ns.compat |= CF_MEMORY;
                        }
                    } else if str_eq(pname, b"reg") && vlen >= 8 && !ns.has_reg {
                        ns.reg = be64_2cell(vdata);
                        ns.reg_size = if vlen >= 16 { be64_2cell(vdata.add(8)) } else { 0 };
                        ns.has_reg = true;
                        if vlen >= 32 {
                            ns.reg2 = be64_2cell(vdata.add(16));
                            ns.has_reg2 = true;
                        }
                    } else if str_eq(pname, b"ranges") && vlen > 0 {
                        ns.ranges_data = vdata;
                        ns.ranges_len = vlen;
                    } else if str_eq(pname, b"interrupt-map") {
                        ns.int_map_data = vdata;
                        ns.int_map_len = vlen;
                    } else if str_eq(pname, b"interrupts") && vlen >= 12 && !ns.has_irq {
                        let irq_type = be32(vdata);
                        let irq_num = be32(vdata.add(4));
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

            FDT_END => return,

            _ => return, // corrupted DTB
        }
    }
}

// ============================================================================
// Public Rust API — for Rust crate consumers (serial_rs, drivers_rs, etc.)
// ============================================================================

/// Return a reference to the global parsed FDT info.
///
/// # Safety
/// Caller must ensure `fdt_init()` has been called first.
pub unsafe fn info() -> &'static FdtInfo {
    &*(&raw const G_INFO)
}

// ============================================================================
// Public API
// ============================================================================

/// Parse the DTB at the given physical address.
/// Safe to call with dtb_addr=0 (no-op).
pub fn fdt_init(dtb_addr: u64) {
    #[cfg(target_arch = "aarch64")]
    unsafe { parse_dtb(dtb_addr); }
    #[cfg(not(target_arch = "aarch64"))]
    { let _ = dtb_addr; }
}

/// Return a pointer to the parsed FDT info.
pub fn fdt_info_ptr() -> *const FdtInfo {
    unsafe { &raw const G_INFO }
}

/// Copy the parsed FDT info to the caller's buffer.
pub fn fdt_get_info(out: *mut FdtInfo) {
    unsafe { ptr::copy_nonoverlapping(&raw const G_INFO, out, 1); }
}
