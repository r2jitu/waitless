// tools/hvf-runner/src/fdt.rs
//
// FDT blob generator using the vm-fdt crate (from rust-vmm).
// Produces a DTB that the kernel's fdt.rs parser accepts.

use vm_fdt::FdtWriter;

/// A virtio-mmio device to place in the FDT.
pub struct VirtioMmioDesc {
    pub base: u64,
    pub size: u64,
    /// GIC SPI number (the FDT `interrupts` property encodes
    /// `<type=0 spi_number flags>` and the kernel adds 32 to get the INTID).
    pub spi: u32,
}

/// Generate a complete FDT blob for the HVF runner VM.
///
/// The runner deliberately does NOT advertise a PL011 UART here.
/// The kernel's `serial::aarch64::init` prefers `uart_base` from
/// the FDT when present, and only falls through to virtio-mmio
/// console (DeviceID=3) when no UART is advertised. We want the
/// virtio-console path on HVF for transport uniformity with KVM
/// and to retire the runner's bespoke 8-byte-per-write PL011 trick;
/// QEMU's `-machine virt` still publishes PL011 in *its* FDT, so
/// the same kernel binary keeps working under QEMU TCG.
pub fn generate(
    ram_base: u64,
    ram_size: u64,
    gicd_base: u64,
    gicr_base: u64,
    cpu_count: usize,
    virtio_devices: &[VirtioMmioDesc],
) -> Vec<u8> {
    let mut fdt = FdtWriter::new().unwrap();

    // Root node
    let root = fdt.begin_node("").unwrap();
    fdt.property_u32("#address-cells", 2).unwrap();
    fdt.property_u32("#size-cells", 2).unwrap();
    fdt.property_string("compatible", "linux,dummy-virt").unwrap();

    // /psci — the guest uses HVC-based PSCI for CPU_ON/SYSTEM_OFF.
    let psci = fdt.begin_node("psci").unwrap();
    fdt.property_string("compatible", "arm,psci-0.2").unwrap();
    fdt.property_string("method", "hvc").unwrap();
    fdt.end_node(psci).unwrap();

    // /cpus
    let cpus = fdt.begin_node("cpus").unwrap();
    fdt.property_u32("#address-cells", 1).unwrap();
    fdt.property_u32("#size-cells", 0).unwrap();
    for i in 0..cpu_count {
        let cpu = fdt.begin_node(&format!("cpu@{i}")).unwrap();
        fdt.property_string("device_type", "cpu").unwrap();
        fdt.property_string("compatible", "arm,cortex-a72").unwrap();
        fdt.property_u32("reg", i as u32).unwrap();
        if cpu_count > 1 {
            fdt.property_string("enable-method", "psci").unwrap();
        }
        fdt.end_node(cpu).unwrap();
    }
    fdt.end_node(cpus).unwrap();

    // /memory@XXXXXXXX
    let mem = fdt.begin_node(&format!("memory@{ram_base:x}")).unwrap();
    fdt.property_string("device_type", "memory").unwrap();
    fdt.property_array_u64("reg", &[ram_base, ram_size]).unwrap();
    fdt.end_node(mem).unwrap();

    // /intc@XXXXXXXX — GICv3
    // Redistributor region: N CPUs × 0x20000 bytes per CPU (2 frames).
    let gicr_size = (cpu_count as u64) * 0x2_0000;
    let gic = fdt.begin_node(&format!("intc@{gicd_base:x}")).unwrap();
    fdt.property_string("compatible", "arm,gic-v3").unwrap();
    fdt.property_u32("#interrupt-cells", 3).unwrap();
    fdt.property_null("interrupt-controller").unwrap();
    fdt.property_array_u64("reg", &[
        gicd_base, 0x1_0000,
        gicr_base, gicr_size,
    ]).unwrap();
    fdt.end_node(gic).unwrap();

    // /virtio_mmio@XXXXXXXX nodes
    for dev in virtio_devices {
        let node = fdt.begin_node(&format!("virtio_mmio@{:x}", dev.base)).unwrap();
        fdt.property_string("compatible", "virtio,mmio").unwrap();
        fdt.property_array_u64("reg", &[dev.base, dev.size]).unwrap();
        // interrupts = <type=0(SPI) spi_number flags=1(edge-rising)>
        fdt.property_array_u32("interrupts", &[0, dev.spi, 1]).unwrap();
        fdt.end_node(node).unwrap();
    }

    // /hvf-yield@9001000 — cooperative yield register.
    // The guest writes to this MMIO address instead of executing WFI.
    // The HVF runner intercepts the stage-2 fault and parks the vCPU
    // thread until the IO thread has data for it (zero host CPU while
    // idle). QEMU FDTs omit this node, so the guest falls back to WFI
    // automatically when it runs on QEMU instead.
    let yield_node = fdt.begin_node("hvf-yield@9001000").unwrap();
    fdt.property_string("compatible", "hvf,yield").unwrap();
    fdt.property_array_u64("reg", &[0x0900_1000, 0x1000]).unwrap();
    fdt.end_node(yield_node).unwrap();

    fdt.end_node(root).unwrap();
    fdt.finish().unwrap()
}
