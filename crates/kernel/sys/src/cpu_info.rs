// kernel/cpu_info.rs — Boot-time CPU + hypervisor identification.
//
// Cheap one-shot inspection of CPUID (x86) / MIDR + ID_AA64ISAR0
// (aarch64) for the boot banner. Format is "vendor (feature, …)" —
// short enough to fit on one serial line, useful enough to tell at
// a glance whether crypto acceleration is wired (`tls_handshake_max`
// numbers shift hugely on AES-NI / FEAT_AES).
//
// All readers are pure register reads; no allocation, no dependency
// on `mm::init` having run.

use core::fmt::{self, Write};

/// Compact summary written into a fixed-size buffer. Returns the
/// number of bytes written. Caller picks the buffer size; ~96 bytes
/// is enough for the longest realistic output.
pub fn summary(buf: &mut [u8]) -> usize {
    let mut w = BufWriter::new(buf);
    let _ = arch::write_cpu(&mut w);
    w.pos
}

/// Returns "KVM" / "TCG" / "HVF" / "Bare metal" / "Unknown". On
/// x86_64 we read CPUID 0x40000000 — the hypervisor-vendor string
/// every modern hypervisor sets. On aarch64 there's no
/// architectural way to detect; we infer from the GIC version
/// (HVF runner uses GICv3, QEMU TCG default uses GICv2) — best
/// effort, may say "Unknown" for novel platforms.
pub fn hypervisor() -> &'static str {
    arch::hypervisor()
}

// ----------------------------------------------------------------------------
// Tiny no_std string writer over a `&mut [u8]`.
// ----------------------------------------------------------------------------

struct BufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> BufWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
}

impl Write for BufWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let room = self.buf.len() - self.pos;
        let n = bytes.len().min(room);
        self.buf[self.pos..self.pos + n].copy_from_slice(&bytes[..n]);
        self.pos += n;
        Ok(())
    }
}

// ----------------------------------------------------------------------------
// x86_64 implementation
// ----------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
mod arch {
    use super::*;

    pub fn write_cpu(w: &mut BufWriter) -> fmt::Result {
        // Vendor — CPUID leaf 0x0 returns the 12-byte vendor string
        // in EBX, EDX, ECX (yes, in that order).
        let (_max_leaf, ebx, ecx, edx) = cpuid(0);
        let mut vbuf = [0u8; 12];
        vbuf[0..4].copy_from_slice(&ebx.to_le_bytes());
        vbuf[4..8].copy_from_slice(&edx.to_le_bytes());
        vbuf[8..12].copy_from_slice(&ecx.to_le_bytes());
        let vendor = match &vbuf {
            b"GenuineIntel" => "Intel",
            b"AuthenticAMD" => "AMD",
            b"  Shanghai  " => "Zhaoxin",
            b"HygonGenuine" => "Hygon",
            _ => "x86",
        };
        write!(w, "{}", vendor)?;

        // Feature bits we care about (CPUID 0x1 ECX/EDX, CPUID 0x7
        // sub-leaf 0 EBX). Only print the ones present, comma-
        // separated, in stable order.
        let (_, _, ecx1, _edx1) = cpuid(1);
        let (_, ebx7, _, _) = cpuid_subleaf(7, 0);
        let mut feats = FeatureList::new(w);
        if ecx1 & (1 << 25) != 0 {
            feats.add("AES-NI")?;
        }
        if ecx1 & (1 << 1) != 0 {
            feats.add("PCLMUL")?;
        }
        if ecx1 & (1 << 28) != 0 {
            feats.add("AVX")?;
        }
        if ebx7 & (1 << 5) != 0 {
            feats.add("AVX2")?;
        }
        if ebx7 & (1 << 3) != 0 {
            feats.add("BMI1")?;
        }
        if ebx7 & (1 << 8) != 0 {
            feats.add("BMI2")?;
        }
        if ecx1 & (1 << 12) != 0 {
            feats.add("FMA")?;
        }
        feats.finish()
    }

    pub fn hypervisor() -> &'static str {
        // Bit 31 of CPUID 0x1 ECX is the "hypervisor present" flag.
        // If set, leaf 0x40000000 returns the hypervisor vendor.
        let (_, _, ecx1, _) = cpuid(1);
        if ecx1 & (1 << 31) == 0 {
            return "Bare metal";
        }
        let (_, ebx, ecx, edx) = cpuid(0x4000_0000);
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&ebx.to_le_bytes());
        buf[4..8].copy_from_slice(&ecx.to_le_bytes());
        buf[8..12].copy_from_slice(&edx.to_le_bytes());
        match &buf {
            b"KVMKVMKVM\0\0\0" => "KVM",
            b"TCGTCGTCGTCG" => "QEMU TCG",
            b"Microsoft Hv" => "Hyper-V",
            b"VMwareVMware" => "VMware",
            b"XenVMMXenVMM" => "Xen",
            b"bhyve bhyve " => "bhyve",
            _ => "Unknown",
        }
    }

    fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
        cpuid_subleaf(leaf, 0)
    }

    fn cpuid_subleaf(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
        let (a, b, c, d): (u32, u32, u32, u32);
        unsafe {
            // LLVM reserves rbx as the inline-asm base pointer in
            // PIC code, so move EBX through a scratch register
            // (same pattern as the SSE-init code in smp.rs).
            core::arch::asm!(
                "mov {tmp:r}, rbx",
                "cpuid",
                "xchg {tmp:r}, rbx",
                tmp = out(reg) b,
                inout("eax") leaf => a,
                inout("ecx") sub => c,
                out("edx") d,
                options(nomem, nostack, preserves_flags),
            );
        }
        (a, b, c, d)
    }
}

// ----------------------------------------------------------------------------
// aarch64 implementation
// ----------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
mod arch {
    use super::*;

    pub fn write_cpu(w: &mut BufWriter) -> fmt::Result {
        // MIDR_EL1: implementer in bits 31:24, part-num in bits
        // 15:4. Implementer 0x61 = Apple Silicon.
        let midr: u64;
        unsafe {
            core::arch::asm!(
                "mrs {0}, MIDR_EL1",
                out(reg) midr,
                options(nomem, nostack, preserves_flags),
            );
        }
        let implementer = ((midr >> 24) & 0xFF) as u8;
        let vendor = match implementer {
            0x41 => "ARM",
            0x42 => "Broadcom",
            0x43 => "Cavium",
            0x44 => "DEC",
            0x46 => "Fujitsu",
            0x4D => "Marvell",
            0x4E => "NVIDIA",
            0x50 => "APM",
            0x51 => "Qualcomm",
            0x56 => "Marvell",
            0x61 => "Apple",
            0x66 => "Faraday",
            0x69 => "Intel",
            _ => "aarch64",
        };
        write!(w, "{}", vendor)?;

        // ID_AA64ISAR0_EL1: AES (bits 7:4), SHA1 (11:8), SHA2 (15:12),
        // CRC32 (19:16), Atomic (23:20). Each 4-bit field: 0 = none,
        // ≥1 = supported (for AES, ≥2 includes PMULL).
        let isar0: u64;
        unsafe {
            core::arch::asm!(
                "mrs {0}, ID_AA64ISAR0_EL1",
                out(reg) isar0,
                options(nomem, nostack, preserves_flags),
            );
        }
        let aes_field = ((isar0 >> 4) & 0xF) as u8;
        let sha1_field = ((isar0 >> 8) & 0xF) as u8;
        let sha2_field = ((isar0 >> 12) & 0xF) as u8;
        let crc32_field = ((isar0 >> 16) & 0xF) as u8;
        let atomic_field = ((isar0 >> 20) & 0xF) as u8;
        let mut feats = FeatureList::new(w);
        if aes_field >= 1 {
            feats.add("AES")?;
        }
        if aes_field >= 2 {
            feats.add("PMULL")?;
        }
        if sha1_field >= 1 {
            feats.add("SHA1")?;
        }
        if sha2_field >= 1 {
            feats.add("SHA2")?;
        }
        if crc32_field >= 1 {
            feats.add("CRC32")?;
        }
        if atomic_field >= 1 {
            feats.add("LSE")?;
        }
        feats.finish()
    }

    pub fn hypervisor() -> &'static str {
        // No architectural way to detect hypervisor on aarch64.
        // Heuristic: GIC version. HVF runner advertises GICv3,
        // QEMU TCG default is GICv2.
        match crate::aarch64::fdt::info().gic_version {
            3 => "HVF / KVM (GICv3)",
            2 => "QEMU TCG (GICv2)",
            _ => "Unknown",
        }
    }
}

// ----------------------------------------------------------------------------
// Shared helper: comma-separated feature list inside parens
// ----------------------------------------------------------------------------

struct FeatureList<'w, 'b> {
    w: &'w mut BufWriter<'b>,
    started: bool,
}

impl<'w, 'b> FeatureList<'w, 'b> {
    fn new(w: &'w mut BufWriter<'b>) -> Self {
        Self { w, started: false }
    }

    fn add(&mut self, feat: &str) -> fmt::Result {
        if !self.started {
            self.w.write_str(" (")?;
            self.started = true;
        } else {
            self.w.write_str(", ")?;
        }
        self.w.write_str(feat)
    }

    fn finish(self) -> fmt::Result {
        if self.started {
            self.w.write_str(")")?;
        }
        Ok(())
    }
}
