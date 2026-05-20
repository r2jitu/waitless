// net/from_bytes.rs — Safe wrapper for parsing byte slices as packed headers.
//
// The dominant unsafe pattern in the net stack is interpreting an inbound
// byte buffer as a `&PacketHeader`:
//
//     let hdr = unsafe { &*(data.as_ptr() as *const TcpHeader) };
//
// Each call site validates length manually first and then casts. The cast
// is unsafe because:
//   1. The byte buffer might be too short (caller's job to check).
//   2. The buffer pointer might be misaligned for the struct.
//   3. The struct's fields might have invalid bit patterns (rare for
//      packet headers, which are usually `Copy` plain-old-data).
//
// `FromBytes` collapses every such site into a single audited helper:
//
//     let hdr = TcpHeader::try_ref_from(data)?;
//
// The trait is `unsafe` to implement (the implementer asserts that any
// bit pattern of `size_of::<Self>()` bytes is a valid `Self`). Calling
// `try_ref_from` is safe.
//
// Implementations must be `#[repr(C, packed)]` so alignment is 1 (no
// alignment requirement on the input pointer) and the layout is fixed.
// `try_ref_from` checks length and reads via `core::ptr::read_unaligned`
// to handle the (usually-zero, but possible) misalignment cleanly.

// See .bazelrc for why this is `cfg_attr(not(test), no_std)` and not bare `#![no_std]`.
#![cfg_attr(not(test), no_std)]

/// Marker trait for types that can be safely reinterpreted from a byte
/// slice. Safety: implementers MUST be `#[repr(C, packed)]` (alignment
/// 1) AND any bit pattern of `size_of::<Self>()` bytes must be a valid
///    `Self`. Concretely: integer fields, byte arrays, and other plain
///    `Copy` POD types are fine; `bool`, `enum`, references, and `NonZero*`
///    are NOT.
pub unsafe trait FromBytes: Sized {
    /// Try to interpret the prefix of `bytes` as `&Self`. Returns `None`
    /// if `bytes.len() < size_of::<Self>()`.
    ///
    /// Note: this returns a *reference* into the input buffer, but it
    /// reads through `*const Self` directly. Because `Self` is
    /// `#[repr(C, packed)]` (alignment 1), there is no alignment
    /// requirement; reads through this reference must use field
    /// projection (which the compiler turns into unaligned loads),
    /// not e.g. `ptr::read` on a raw pointer cast.
    #[inline]
    fn try_ref_from(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        // SAFETY:
        // * Length checked above.
        // * Alignment is 1 because Self is repr(C, packed) — the trait
        //   safety contract requires this.
        // * The bytes are valid for reads for size_of::<Self>().
        // * The trait safety contract guarantees any bit pattern is a
        //   valid Self.
        // * Lifetime is tied to the input slice.
        Some(unsafe { &*(bytes.as_ptr() as *const Self) })
    }

    /// Try to interpret the prefix of `bytes` as `&mut Self`. Same
    /// requirements as `try_ref_from`.
    #[inline]
    fn try_mut_from(bytes: &mut [u8]) -> Option<&mut Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        Some(unsafe { &mut *(bytes.as_mut_ptr() as *mut Self) })
    }

    /// Returns `bytes` reinterpreted as `Self` by value, or None if
    /// the slice is too short. This is the safest variant: it copies
    /// the bytes into a fresh `Self`, so the returned value has no
    /// lifetime relation to the input.
    #[inline]
    fn try_read_from(bytes: &[u8]) -> Option<Self>
    where
        Self: Copy,
    {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        // SAFETY: length checked; read_unaligned handles any alignment;
        // any bit pattern is a valid Self per the trait contract.
        Some(unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const Self) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, packed)]
    #[derive(Clone, Copy, PartialEq, Debug)]
    struct Hdr {
        a: u16,
        b: u32,
        c: u8,
    }

    // SAFETY: repr(C, packed) and all fields are POD integer types.
    unsafe impl FromBytes for Hdr {}

    #[test]
    fn try_ref_from_short() {
        let bytes = [0u8; 3];
        assert!(Hdr::try_ref_from(&bytes).is_none());
    }

    #[test]
    fn try_ref_from_exact() {
        let bytes = [
            0x12, 0x34, // a = 0x3412 (LE)
            0x78, 0x56, 0x34, 0x12, // b = 0x12345678 (LE)
            0xAB, // c
        ];
        let hdr = Hdr::try_ref_from(&bytes).unwrap();
        let a = hdr.a;
        let b = hdr.b;
        let c = hdr.c;
        assert_eq!(a, 0x3412);
        assert_eq!(b, 0x12345678);
        assert_eq!(c, 0xAB);
    }

    #[test]
    fn try_ref_from_extra_bytes() {
        let bytes = [
            0x12, 0x34, 0x78, 0x56, 0x34, 0x12, 0xAB, 0xFF, 0xFF,
            0xFF, // extra trailing bytes — ignored
        ];
        let hdr = Hdr::try_ref_from(&bytes).unwrap();
        let a = hdr.a;
        assert_eq!(a, 0x3412);
    }

    #[test]
    fn try_read_from_copies() {
        let bytes = [0x12, 0x34, 0x78, 0x56, 0x34, 0x12, 0xAB];
        let hdr: Hdr = Hdr::try_read_from(&bytes).unwrap();
        // Mutate a local copy after the read; hdr should be unaffected.
        // (`hdr.a` is read into a local because Hdr is #[repr(packed)]
        //  and taking a reference to a packed field is undefined.)
        let mut bytes_copy = bytes;
        bytes_copy[0] = 0xFF;
        assert_eq!(bytes_copy[0], 0xFF);
        let a = hdr.a;
        assert_eq!(a, 0x3412);
    }

    #[test]
    fn try_mut_from_writes() {
        let mut bytes = [0u8; 7];
        {
            let hdr = Hdr::try_mut_from(&mut bytes).unwrap();
            hdr.a = 0xBEEF;
            hdr.c = 0x99;
        }
        // First two bytes should be 0xEF, 0xBE (LE encoding)
        assert_eq!(bytes[0], 0xEF);
        assert_eq!(bytes[1], 0xBE);
        assert_eq!(bytes[6], 0x99);
    }
}
