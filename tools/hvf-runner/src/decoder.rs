// tools/hvf-runner/src/decoder.rs
//
// Aarch64 load/store instruction decoder for MMIO trap handling.
//
// When HVF delivers a stage-2 data abort (EC=0x24), the exit struct
// gives us the faulting IPA but NOT what instruction caused it (the
// ARM ISV=0 problem). We must fetch the instruction word from guest
// RAM via the host mapping and decode it ourselves.
//
// The kernel uses `core::ptr::read_volatile` / `write_volatile` for
// all device access. With release-mode LLVM on aarch64, these compile
// to exactly four instruction forms (verified by disassembling
// webserver.elf). We handle only these; unknown encodings panic with
// the instruction word so adding new cases is fix-forward.

/// Decoded MMIO access information.
#[derive(Debug)]
pub struct MmioAccess {
    /// Access width in bytes: 1 or 4.
    pub size: u8,
    /// true = store (guest writing to device), false = load (guest reading).
    pub is_write: bool,
    /// General-purpose register index (0..30). For stores, the runner
    /// reads the value from this register via `hv_vcpu_get_reg`. For
    /// loads, the runner writes the device's response into this register
    /// via `hv_vcpu_set_reg`.
    ///
    /// Index 31 means XZR/WZR (zero register) — stores always write 0,
    /// loads discard the result.
    pub rt: u8,
}

/// Decode a 32-bit aarch64 instruction word into an MMIO access
/// descriptor. Returns `None` for unrecognised encodings.
///
/// We don't need to decode the immediate offset because HVF already
/// gives us the faulting IPA in `exit.exception.physical_address`.
pub fn decode(instr: u32) -> Option<MmioAccess> {
    // Bits 31:22 determine the instruction class for the forms we care
    // about. We mask with 0xffc00000 and match on the known values.
    //
    // The Rt (destination/source register) field is always bits 4:0.
    let rt = (instr & 0x1f) as u8;

    match instr & 0xffc0_0000 {
        // LDR Wt, [Xn{, #imm12}]  — 32-bit unsigned-offset load
        0xb940_0000 => Some(MmioAccess { size: 4, is_write: false, rt }),

        // STR Wt, [Xn{, #imm12}]  — 32-bit unsigned-offset store
        0xb900_0000 => Some(MmioAccess { size: 4, is_write: true, rt }),

        // LDRB Wt, [Xn{, #imm12}] — 8-bit unsigned-offset load
        0x3940_0000 => Some(MmioAccess { size: 1, is_write: false, rt }),

        // STRB Wt, [Xn{, #imm12}] — 8-bit unsigned-offset store
        0x3900_0000 => Some(MmioAccess { size: 1, is_write: true, rt }),

        // LDR Xt, [Xn{, #imm12}]  — 64-bit unsigned-offset load
        // Needed if the kernel ever does a 64-bit MMIO read (rare but
        // possible for GIC IROUTER if native vGIC doesn't catch it).
        0xf940_0000 => Some(MmioAccess { size: 8, is_write: false, rt }),

        // STR Xt, [Xn{, #imm12}]  — 64-bit unsigned-offset store
        0xf900_0000 => Some(MmioAccess { size: 8, is_write: true, rt }),

        // LDRH Wt, [Xn{, #imm12}] — 16-bit unsigned-offset load
        0x7940_0000 => Some(MmioAccess { size: 2, is_write: false, rt }),

        // STRH Wt, [Xn{, #imm12}] — 16-bit unsigned-offset store
        0x7900_0000 => Some(MmioAccess { size: 2, is_write: true, rt }),

        _ => {
            // Check for post-indexed forms (bits 29:27 = 111, bits 26:24 = 000,
            // bits 11:10 = 01). These appear in the kernel's GIC IROUTER
            // init loop: `str xzr, [x9], #8`.
            let size_bits = (instr >> 30) & 3;
            let is_unpriv_or_post = (instr >> 10) & 3;
            let class_bits = (instr >> 24) & 0x3f; // bits 29:24

            if class_bits == 0b111_000 && is_unpriv_or_post == 0b01 {
                // Post-indexed load/store.
                let is_load = (instr >> 22) & 1 == 1;
                let size = 1u8 << size_bits; // 1, 2, 4, 8
                Some(MmioAccess {
                    size,
                    is_write: !is_load,
                    rt,
                })
            } else if class_bits == 0b111_000 && is_unpriv_or_post == 0b00 {
                // STUR/LDUR (unscaled immediate offset).
                let is_load = (instr >> 22) & 1 == 1;
                let size = 1u8 << size_bits;
                Some(MmioAccess {
                    size,
                    is_write: !is_load,
                    rt,
                })
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_str_w1_x0() {
        // str w1, [x0]  →  encoding 0xb9000001
        let a = decode(0xb900_0001).unwrap();
        assert_eq!(a.size, 4);
        assert!(a.is_write);
        assert_eq!(a.rt, 1);
    }

    #[test]
    fn decode_ldr_w9_x8_imm() {
        // ldr w9, [x8, #0x18]  →  encoding 0xb9401909
        let a = decode(0xb940_1909).unwrap();
        assert_eq!(a.size, 4);
        assert!(!a.is_write);
        assert_eq!(a.rt, 9);
    }

    #[test]
    fn decode_strb_wzr() {
        // strb wzr, [x19]  →  encoding 0x3900027f
        let a = decode(0x3900_027f).unwrap();
        assert_eq!(a.size, 1);
        assert!(a.is_write);
        assert_eq!(a.rt, 31); // wzr
    }

    #[test]
    fn decode_unknown_returns_none() {
        // ldp x0, x1, [sp] — pair load, not handled
        assert!(decode(0xa940_07e0).is_none());
    }
}
