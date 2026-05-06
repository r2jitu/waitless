// kernel/aarch64/fdt.rs — FDT (Device Tree Blob) discovery for ARM64
//
// Walks the device tree looking for the platform devices we care about
// (PL011 UART, virtio-mmio, GIC distributor/redistributor, PCIe ECAM) and
// populates an `FdtInfo` struct used during boot. Parsing is delegated to
// the upstream `fdt` crate; this file is the kernel-specific extraction
// layer that knows about GIC SPI/PPI offsets, PCI 32-bit MMIO ranges, and
// the interrupt-map → slot table.
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
    /// Per-device interrupt flags from FDT. Bit 0: 1=edge, 0=level.
    pub virtio_irq_flags: [u32; 32],
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
    /// HVF cooperative yield MMIO base address. When non-zero, the guest
    /// writes to this address instead of executing WFI, allowing the HVF
    /// runner to park the vCPU thread at zero CPU cost. Discovered from
    /// an `hvf-yield` FDT node (only present in HVF runner FDTs).
    pub yield_mmio_base: u64,
    /// Kernel command line — `chosen.bootargs` from the FDT, copied
    /// into an inline buffer at parse time. Capped at
    /// `BOOT_ARGS_MAX` bytes; longer strings are truncated. We use a
    /// fixed buffer (rather than `Box::leak`) because FDT parsing
    /// runs before heap init in the boot sequence. Access via
    /// `boot_args()` for a `&'static str` view.
    boot_args_buf: [u8; BOOT_ARGS_MAX],
    boot_args_len: usize,
}

/// Cap on the bytes we keep from `chosen.bootargs`. 256 bytes is
/// more than any real kernel command line we care about and keeps
/// `FdtInfo` cheap to copy/initialise.
pub const BOOT_ARGS_MAX: usize = 256;

impl FdtInfo {
    const ZEROED: FdtInfo = FdtInfo {
        uart_base: 0,
        virtio_bases: [0; 32],
        virtio_irqs: [0; 32],
        virtio_irq_flags: [0; 32],
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
        yield_mmio_base: 0,
        boot_args_buf: [0; BOOT_ARGS_MAX],
        boot_args_len: 0,
    };

    /// `&'static str` view into the inlined boot-args buffer. Lifetime
    /// is `&'static` because `FdtInfo` lives in `G_INFO: InitOnce<…>`
    /// for the kernel's lifetime, so the reborrowed slice does too.
    pub fn boot_args(&'static self) -> &'static str {
        let bytes = &self.boot_args_buf[..self.boot_args_len];
        core::str::from_utf8(bytes).unwrap_or("")
    }
}

/// Parsed FDT, populated exactly once by `init()` before any AP starts.
static G_INFO: InitOnce<FdtInfo> = InitOnce::new();

// ============================================================================
// Big-endian helpers — used to parse raw `ranges` and `interrupt-map`
// property bytes that the fdt crate exposes as `&[u8]`.
// ============================================================================

#[cfg(target_arch = "aarch64")]
#[inline]
fn be32(s: &[u8]) -> u32 {
    u32::from_be_bytes([s[0], s[1], s[2], s[3]])
}

// ============================================================================
// Per-protocol GIC interrupt translation
// ============================================================================
//
// The Device Tree `interrupts` property for a GIC consumer encodes
// `(type, number, flags)`:
//   type 0 → SPI (Shared Peripheral Interrupt), GIC INTID = number + 32
//   type 1 → PPI (Private Peripheral Interrupt), GIC INTID = number + 16
//
// The `fdt` crate's `interrupts()` iterator returns each cell flattened to
// `usize`, so we read the raw bytes ourselves to keep the (type, num) pair.
#[cfg(target_arch = "aarch64")]
fn translate_gic_irq(int_type: u32, int_num: u32) -> u32 {
    if int_type == 0 { int_num + 32 } else { int_num + 16 }
}

#[cfg(target_arch = "aarch64")]
/// Parse `interrupts = <type spi_num flags>` from FDT.
/// Returns (intid, flags) where flags bit 0 = 1 for edge-triggered.
fn parse_first_interrupt(prop: &[u8]) -> Option<(u32, u32)> {
    if prop.len() < 12 { return None; }
    let int_type = be32(prop);
    let int_num = be32(&prop[4..]);
    let flags = be32(&prop[8..]);
    Some((translate_gic_irq(int_type, int_num), flags))
}

// ============================================================================
// PCI ranges parser — extracts the 32-bit MMIO aperture
// ============================================================================
//
// PCI host `ranges` property layout (per PCI bus binding):
//   child_high (1 cell): flags
//   child_mid  (1 cell): pci addr high
//   child_low  (1 cell): pci addr low
//   parent_high (1 cell): cpu addr high
//   parent_low  (1 cell): cpu addr low
//   size_high   (1 cell): size high
//   size_low    (1 cell): size low
// Total: 28 bytes per range.
//
// flags >> 24 & 3: 0=config, 1=I/O, 2=32-bit memory, 3=64-bit memory.

#[cfg(target_arch = "aarch64")]
fn parse_pci_mmio32(ranges: &[u8]) -> Option<(u64, u64)> {
    let mut off = 0;
    while off + 28 <= ranges.len() {
        let flags = be32(&ranges[off..]);
        let space = (flags >> 24) & 3;
        if space == 2 {
            let cpu_hi = be32(&ranges[off + 12..]) as u64;
            let cpu_lo = be32(&ranges[off + 16..]) as u64;
            let size_hi = be32(&ranges[off + 20..]) as u64;
            let size_lo = be32(&ranges[off + 24..]) as u64;
            return Some(((cpu_hi << 32) | cpu_lo, (size_hi << 32) | size_lo));
        }
        off += 28;
    }
    None
}

// ============================================================================
// PCI interrupt-map parser — slot → GIC INTID
// ============================================================================
//
// `interrupt-map` is variable-width but for QEMU virt and Apple hypervisors
// it's 40 bytes per entry:
//   child_addr  (3 cells = 12 bytes): pci unit address (slot in bits 11-15 of [0])
//   child_int   (1 cell  =  4 bytes): pin
//   parent      (1 cell  =  4 bytes): phandle
//   parent_addr (2 cells =  8 bytes): zero
//   parent_int  (3 cells = 12 bytes): GIC type, GIC irq, flags

#[cfg(target_arch = "aarch64")]
fn parse_pci_interrupt_map(imap: &[u8], pci_irqs: &mut [u32; 8]) {
    let mut off = 0;
    while off + 40 <= imap.len() {
        let child_hi = be32(&imap[off..]);
        let gic_type = be32(&imap[off + 28..]);
        let gic_irq = be32(&imap[off + 32..]);
        let slot = ((child_hi >> 11) & 0x1F) as usize;
        let intid = translate_gic_irq(gic_type, gic_irq);
        if slot < 8 && pci_irqs[slot] == 0 {
            pci_irqs[slot] = intid;
        }
        off += 40;
    }
}

// ============================================================================
// Main parser — populates an FdtInfo from a parsed Fdt
// ============================================================================

#[cfg(target_arch = "aarch64")]
fn extract_info(fdt: &fdt::Fdt) -> FdtInfo {
    let mut info = FdtInfo::ZEROED;

    info.cpu_count = fdt.cpus().count() as u32;

    if let Some(region) = fdt.memory().regions().next() {
        info.ram_base = region.starting_address as u64;
        info.ram_size = region.size.unwrap_or(0) as u64;
    }

    if let Some(uart) = fdt.find_compatible(&["arm,pl011"]) {
        if let Some(reg) = uart.reg().and_then(|mut r| r.next()) {
            info.uart_base = reg.starting_address as u64;
        }
    }

    // GIC: try v3 first, fall back to v2 names.
    let gic = fdt
        .find_compatible(&["arm,gic-v3"])
        .map(|n| (n, 3u8))
        .or_else(|| {
            fdt.find_compatible(&["arm,gic-400", "arm,cortex-a15-gic"])
                .map(|n| (n, 2u8))
        });
    if let Some((node, version)) = gic {
        info.gic_version = version;
        let mut regs = node.reg().into_iter().flatten();
        if let Some(r) = regs.next() {
            info.gic_dist_base = r.starting_address as u64;
        }
        if version == 3 {
            if let Some(r) = regs.next() {
                info.gic_redist_base = r.starting_address as u64;
            }
        }
    }

    // virtio-mmio: walk every node in the tree and pick those whose
    // compatible includes "virtio,mmio". The fdt crate doesn't expose a
    // typed "find_all_compatible" helper, so we do the filter ourselves.
    for node in fdt.find_all_nodes("/").flat_map(|root| root.children()) {
        scan_for_virtio(&node, &mut info);
    }
    // Also scan /soc and /soc/* in case the layout uses an SoC sub-node.
    if let Some(soc) = fdt.find_node("/soc") {
        for node in soc.children() {
            scan_for_virtio(&node, &mut info);
        }
    }

    // PCIe ECAM (host bridge).
    if let Some(pci) = fdt.find_compatible(&["pci-host-ecam-generic"]) {
        if let Some(reg) = pci.reg().and_then(|mut r| r.next()) {
            info.pcie_ecam_base = reg.starting_address as u64;
            info.pcie_ecam_size = reg.size.unwrap_or(0) as u64;
        }
        if let Some(ranges) = pci.property("ranges") {
            if let Some((base, size)) = parse_pci_mmio32(ranges.value) {
                info.pci_mmio32_base = base;
                info.pci_mmio32_size = size;
            }
        }
        if let Some(imap) = pci.property("interrupt-map") {
            parse_pci_interrupt_map(imap.value, &mut info.pci_irqs);
        }
    }

    // HVF cooperative yield register.
    if let Some(node) = fdt.find_compatible(&["hvf,yield"]) {
        if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
            info.yield_mmio_base = reg.starting_address as u64;
        }
    }

    // /chosen/bootargs — kernel command line. Some firmwares
    // (HVF runner with `--bootargs`, recent QEMU `-append`) emit
    // this; older builds skip the node entirely. Strip a single
    // trailing NUL because the FDT property value usually
    // includes one (it's a length-prefixed C string in the spec).
    // Copy into the inline buffer; truncate (don't fail) if the
    // string overflows BOOT_ARGS_MAX so a too-long arg degrades
    // gracefully.
    if let Some(chosen) = fdt.find_node("/chosen") {
        if let Some(prop) = chosen.property("bootargs") {
            let mut bytes = prop.value;
            if let Some((&last, head)) = bytes.split_last() {
                if last == 0 {
                    bytes = head;
                }
            }
            let n = bytes.len().min(BOOT_ARGS_MAX);
            info.boot_args_buf[..n].copy_from_slice(&bytes[..n]);
            info.boot_args_len = n;
        }
    }

    info
}

#[cfg(target_arch = "aarch64")]
fn scan_for_virtio(node: &fdt::node::FdtNode<'_, '_>, info: &mut FdtInfo) {
    if info.virtio_count >= 32 {
        return;
    }
    let is_virtio = node
        .compatible()
        .map(|c| c.all().any(|s| s == "virtio,mmio"))
        .unwrap_or(false);
    if !is_virtio {
        return;
    }
    let base = match node.reg().and_then(|mut r| r.next()) {
        Some(r) => r.starting_address as u64,
        None => return,
    };
    let (irq, irq_flags) = node
        .property("interrupts")
        .and_then(|p| parse_first_interrupt(p.value))
        .unwrap_or((0, 0));
    let idx = info.virtio_count as usize;
    info.virtio_bases[idx] = base;
    info.virtio_irqs[idx] = irq;
    info.virtio_irq_flags[idx] = irq_flags;
    info.virtio_count += 1;
}

// ============================================================================
// Public API
// ============================================================================

/// Return a reference to the global parsed FDT info. Panics if `init`
/// has not been called yet (which would indicate a boot ordering bug).
pub fn info() -> &'static FdtInfo {
    G_INFO.get()
}

/// Return a pointer to the parsed FDT info. Used by code that needs a
/// raw pointer (e.g., FFI). Panics if `init` has not been called.
pub fn info_ptr() -> *const FdtInfo {
    G_INFO.get() as *const FdtInfo
}

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
        // SAFETY: On bare-metal aarch64 the DTB is loaded by the firmware
        // (QEMU or the HVF runner) at a stable physical address that's
        // identity- or HHDM-mapped. The fdt crate reads the header to find
        // the total length, then bounds-checks every subsequent access.
        let parsed = unsafe { fdt::Fdt::from_ptr(dtb_addr as *const u8) }
            .map(|fdt| extract_info(&fdt))
            .unwrap_or(FdtInfo::ZEROED);
        G_INFO.init(parsed);
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = dtb_addr;
    }
}
