// tools/hvf-runner/src/fdt.rs
//
// Minimal FDT (Flattened Device Tree) blob generator. Produces a DTB
// that the kernel's fdt.rs parser (via the `fdt` crate) accepts.
//
// Only the nodes the kernel actually looks for are included:
//   /cpus/cpu@0       — cpu count (fdt.cpus().count())
//   /memory@XXXXXXXX  — RAM base + size
//   /pl011@9000000    — UART (fdt.find_compatible("arm,pl011"))
//   /intc@8000000     — GICv3 distributor + redistributor
//   /virtio_mmio@...  — one node per virtio-mmio device
//
// No PCI, no /chosen, no bootargs — the kernel doesn't require them.

use std::collections::HashMap;

// FDT v17 token types.
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_END: u32 = 9;

// FDT header fields.
const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_VERSION: u32 = 17;
const FDT_LAST_COMP_VERSION: u32 = 16;

/// A virtio-mmio device to place in the FDT.
pub struct VirtioMmioDesc {
    pub base: u64,
    pub size: u64,
    /// GIC SPI number (NOT the raw INTID — the FDT `interrupts` property
    /// encodes `<type=0 spi_number flags>` and the kernel adds 32).
    pub spi: u32,
}

/// Generate a complete FDT blob for the HVF runner VM.
///
/// Arguments:
///   ram_base, ram_size — guest physical RAM region
///   gicd_base          — GICv3 distributor IPA (from hv_gic_config)
///   gicr_base          — redistributor IPA (from hv_gic_get_redistributor_base)
///   uart_base           — PL011 base IPA
///   virtio_devices      — list of virtio-mmio devices to expose
///
/// Returns the DTB as a `Vec<u8>`, ready to be written into guest RAM.
pub fn generate(
    ram_base: u64,
    ram_size: u64,
    gicd_base: u64,
    gicr_base: u64,
    uart_base: u64,
    virtio_devices: &[VirtioMmioDesc],
) -> Vec<u8> {
    let mut b = Builder::new();

    b.begin_node("");
    b.prop_u32("#address-cells", 2);
    b.prop_u32("#size-cells", 2);
    b.prop_str("compatible", "linux,dummy-virt");

    // /cpus
    b.begin_node("cpus");
    b.prop_u32("#address-cells", 1);
    b.prop_u32("#size-cells", 0);
    b.begin_node("cpu@0");
    b.prop_str("device_type", "cpu");
    b.prop_str("compatible", "arm,cortex-a72");
    b.prop_u32("reg", 0);
    b.end_node(); // cpu@0
    b.end_node(); // cpus

    // /memory@XXXXXXXX
    let mem_name = format!("memory@{ram_base:x}");
    b.begin_node(&mem_name);
    b.prop_str("device_type", "memory");
    b.prop_u64_pair("reg", ram_base, ram_size);
    b.end_node();

    // /pl011@XXXXXXXX
    let uart_name = format!("pl011@{uart_base:x}");
    b.begin_node(&uart_name);
    b.prop_strs("compatible", &["arm,pl011", "arm,primecell"]);
    b.prop_u64_pair("reg", uart_base, 0x1000);
    b.end_node();

    // /intc@XXXXXXXX — GICv3
    let gic_name = format!("intc@{gicd_base:x}");
    b.begin_node(&gic_name);
    b.prop_str("compatible", "arm,gic-v3");
    b.prop_u32("#interrupt-cells", 3);
    b.prop_empty("interrupt-controller");
    // reg: <distributor_base distributor_size redistributor_base redistributor_size>
    let mut reg_buf = Vec::new();
    reg_buf.extend(0u32.to_be_bytes()); // dist addr high
    reg_buf.extend((gicd_base as u32).to_be_bytes()); // dist addr low
    reg_buf.extend(0u32.to_be_bytes()); // dist size high
    reg_buf.extend(0x1_0000u32.to_be_bytes()); // dist size low (64KB)
    reg_buf.extend(0u32.to_be_bytes()); // redist addr high
    reg_buf.extend((gicr_base as u32).to_be_bytes()); // redist addr low
    reg_buf.extend(0u32.to_be_bytes()); // redist size high
    reg_buf.extend(0x2_0000u32.to_be_bytes()); // redist size low (128KB)
    b.prop_raw("reg", &reg_buf);
    b.end_node();

    // /virtio_mmio@XXXXXXXX nodes
    for dev in virtio_devices {
        let name = format!("virtio_mmio@{:x}", dev.base);
        b.begin_node(&name);
        b.prop_str("compatible", "virtio,mmio");
        b.prop_u64_pair("reg", dev.base, dev.size);
        // interrupts = <type=0(SPI) spi_number flags=1(edge-rising)>
        let mut irq = Vec::new();
        irq.extend(0u32.to_be_bytes()); // type 0 = SPI
        irq.extend(dev.spi.to_be_bytes()); // SPI number
        irq.extend(1u32.to_be_bytes()); // flags: edge-triggered
        b.prop_raw("interrupts", &irq);
        b.end_node();
    }

    b.end_node(); // root
    b.finish()
}

// ── Internal DTB builder ─────────────────────────────────────────────────────

struct Builder {
    /// Struct block (FDT tokens + data).
    dt_struct: Vec<u8>,
    /// String block (null-terminated property names, de-duplicated).
    dt_strings: Vec<u8>,
    /// Name → offset into dt_strings for de-duplication.
    string_offsets: HashMap<String, u32>,
}

impl Builder {
    fn new() -> Self {
        Builder {
            dt_struct: Vec::with_capacity(4096),
            dt_strings: Vec::with_capacity(512),
            string_offsets: HashMap::new(),
        }
    }

    fn put_u32(&mut self, v: u32) {
        self.dt_struct.extend(v.to_be_bytes());
    }

    fn begin_node(&mut self, name: &str) {
        self.put_u32(FDT_BEGIN_NODE);
        self.dt_struct.extend(name.as_bytes());
        self.dt_struct.push(0); // null terminator
        // Pad to 4-byte alignment.
        while self.dt_struct.len() % 4 != 0 {
            self.dt_struct.push(0);
        }
    }

    fn end_node(&mut self) {
        self.put_u32(FDT_END_NODE);
    }

    fn intern_string(&mut self, name: &str) -> u32 {
        if let Some(&off) = self.string_offsets.get(name) {
            return off;
        }
        let off = self.dt_strings.len() as u32;
        self.dt_strings.extend(name.as_bytes());
        self.dt_strings.push(0);
        self.string_offsets.insert(name.to_string(), off);
        off
    }

    fn prop_raw(&mut self, name: &str, data: &[u8]) {
        let nameoff = self.intern_string(name);
        self.put_u32(FDT_PROP);
        self.put_u32(data.len() as u32); // value length
        self.put_u32(nameoff); // offset into strings block
        self.dt_struct.extend(data);
        while self.dt_struct.len() % 4 != 0 {
            self.dt_struct.push(0);
        }
    }

    fn prop_u32(&mut self, name: &str, v: u32) {
        self.prop_raw(name, &v.to_be_bytes());
    }

    fn prop_str(&mut self, name: &str, s: &str) {
        let mut data: Vec<u8> = s.as_bytes().to_vec();
        data.push(0);
        self.prop_raw(name, &data);
    }

    fn prop_strs(&mut self, name: &str, ss: &[&str]) {
        let mut data = Vec::new();
        for s in ss {
            data.extend(s.as_bytes());
            data.push(0);
        }
        self.prop_raw(name, &data);
    }

    fn prop_u64_pair(&mut self, name: &str, a: u64, b: u64) {
        let mut data = Vec::new();
        data.extend((a >> 32).to_be_bytes()); // high cell
        data.extend((a as u32).to_be_bytes()); // low cell
        data.extend((b >> 32).to_be_bytes());
        data.extend((b as u32).to_be_bytes());
        self.prop_raw(name, &data);
    }

    fn prop_empty(&mut self, name: &str) {
        self.prop_raw(name, &[]);
    }

    fn finish(mut self) -> Vec<u8> {
        // End the struct block.
        self.put_u32(FDT_END);

        // Assemble the full DTB.
        let header_size = 40; // 10 × u32
        let mem_rsv_size = 16; // one empty reservation entry (two u64 zeros)
        let off_dt_struct = header_size + mem_rsv_size;
        let off_dt_strings = off_dt_struct + self.dt_struct.len();
        let total_size = off_dt_strings + self.dt_strings.len();

        let mut dtb = Vec::with_capacity(total_size);

        // Header (10 × big-endian u32).
        dtb.extend(FDT_MAGIC.to_be_bytes());
        dtb.extend((total_size as u32).to_be_bytes());
        dtb.extend((off_dt_struct as u32).to_be_bytes());
        dtb.extend((off_dt_strings as u32).to_be_bytes());
        dtb.extend((off_dt_struct as u32).to_be_bytes()); // off_mem_rsvmap = off_dt_struct - mem_rsv_size... wait

        // Fix: mem reservation map comes before dt_struct.
        // Re-calculate: off_mem_rsvmap = header_size
        dtb.clear();

        let off_mem_rsvmap = header_size;
        let off_dt_struct = off_mem_rsvmap + mem_rsv_size;
        let off_dt_strings = off_dt_struct + self.dt_struct.len();
        let total_size = off_dt_strings + self.dt_strings.len();

        dtb.extend(FDT_MAGIC.to_be_bytes());
        dtb.extend((total_size as u32).to_be_bytes());
        dtb.extend((off_dt_struct as u32).to_be_bytes());
        dtb.extend((off_dt_strings as u32).to_be_bytes());
        dtb.extend((off_mem_rsvmap as u32).to_be_bytes());
        dtb.extend(FDT_VERSION.to_be_bytes());
        dtb.extend(FDT_LAST_COMP_VERSION.to_be_bytes());
        dtb.extend(0u32.to_be_bytes()); // boot_cpuid_phys
        dtb.extend((self.dt_strings.len() as u32).to_be_bytes()); // size_dt_strings
        dtb.extend((self.dt_struct.len() as u32).to_be_bytes()); // size_dt_struct

        // Memory reservation map: one empty entry (address=0, size=0).
        dtb.extend(0u64.to_be_bytes());
        dtb.extend(0u64.to_be_bytes());

        // Struct block.
        dtb.extend(&self.dt_struct);

        // Strings block.
        dtb.extend(&self.dt_strings);

        dtb
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_parses_successfully() {
        let dtb = generate(
            0x4000_0000,
            128 * 1024 * 1024,
            0x0800_0000,
            0x080a_0000,
            0x0900_0000,
            &[VirtioMmioDesc {
                base: 0x0a00_0000,
                size: 0x200,
                spi: 3,
            }],
        );

        // Check FDT magic.
        assert_eq!(
            u32::from_be_bytes([dtb[0], dtb[1], dtb[2], dtb[3]]),
            FDT_MAGIC
        );
        // Check total size matches actual length.
        let total = u32::from_be_bytes([dtb[4], dtb[5], dtb[6], dtb[7]]) as usize;
        assert_eq!(total, dtb.len());
        // Check it contains expected strings.
        let s = String::from_utf8_lossy(&dtb);
        assert!(s.contains("arm,pl011"));
        assert!(s.contains("arm,gic-v3"));
        assert!(s.contains("virtio,mmio"));
        assert!(s.contains("memory@"));
    }
}
