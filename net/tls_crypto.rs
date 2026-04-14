// net/tls_crypto.rs — ChaCha20, Poly1305, ChaCha20Poly1305 AEAD (RFC 8439).
//
// Hand-rolled pure-Rust implementations of the TLS 1.3 /
// TLS_CHACHA20_POLY1305_SHA256 AEAD. These replace the `chacha20poly1305`
// crate for bare-metal builds because its `cpufeatures`-gated SIMD path
// refuses to compile on `x86_64-unknown-none`.
//
// References:
//   RFC 8439 §2.3  ChaCha20 block function
//   RFC 8439 §2.5  Poly1305 algorithm
//   RFC 8439 §2.8  AEAD_CHACHA20_POLY1305 construction
//
// Constant-timeness:
// - ChaCha20 is naturally constant-time (no data-dependent branches).
// - Poly1305 uses straight-line u64/u128 arithmetic; no lookups, no
//   branches dependent on secret data. The final comparison used for
//   authentication (callers should use `verify`) is constant-time via
//   an OR-of-XORs reduction.
//
// Performance: un-tuned portable code. ~200 MB/s per core on Apple
// Silicon for ChaCha20. Good enough as a correctness baseline; swap
// for a SIMD path later if TLS/QUIC becomes throughput-bound.

#![no_std]

// ============================================================================
// ChaCha20 block function (RFC 8439 §2.3)
// ============================================================================

/// A single 64-byte ChaCha20 keystream block.
pub type Block = [u8; 64];

/// ChaCha20 sigma constant: the 16 ASCII bytes of "expand 32-byte k",
/// interpreted as 4 little-endian u32 words and placed in row 0 of the
/// state matrix.
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

/// Compute one ChaCha20 keystream block.
///
/// * `key` — 32-byte secret key
/// * `counter` — 32-bit block counter (starts at 0 for Poly1305 key
///   derivation, 1 for the first plaintext block)
/// * `nonce` — 12-byte nonce (96 bits, the RFC 8439 form)
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> Block {
    let mut state = [0u32; 16];
    // Row 0: "expand 32-byte k"
    state[0..4].copy_from_slice(&SIGMA);
    // Rows 1-2: key (8 words, little-endian)
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes([
            key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3],
        ]);
    }
    // Row 3: counter || nonce
    state[12] = counter;
    state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

    let initial = state;
    // 20 rounds = 10 × (column quarter-rounds + diagonal quarter-rounds).
    for _ in 0..10 {
        // Columns
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        // Diagonals
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }
    // Serialise: add initial state back and emit as 64 little-endian bytes.
    let mut out = [0u8; 64];
    for i in 0..16 {
        let w = state[i].wrapping_add(initial[i]);
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// Encrypt/decrypt `data` in place with ChaCha20 (XORing the keystream).
/// `counter` is the first-block counter value — pass 1 for record
/// payload encryption, 0 for Poly1305 key derivation.
pub fn chacha20_apply(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut block_counter = counter;
    let mut offset = 0;
    while offset < data.len() {
        let ks = chacha20_block(key, block_counter, nonce);
        let take = core::cmp::min(64, data.len() - offset);
        for i in 0..take {
            data[offset + i] ^= ks[i];
        }
        offset += take;
        block_counter = block_counter.wrapping_add(1);
    }
}

// ============================================================================
// Poly1305 MAC (RFC 8439 §2.5)
// ============================================================================

/// Poly1305 state. Holds the clamped `r`, the add-at-end constant `s`,
/// the 130-bit accumulator as 5 × u32 limbs, and a partial block buffer.
pub struct Poly1305 {
    r: [u32; 5], // 130-bit key, split into 5 × 26-bit limbs
    s: [u32; 4], // add-at-end constant, 4 × 32-bit limbs
    h: [u32; 5], // accumulator, 5 × 26-bit limbs
    buf: [u8; 16],
    buf_len: usize,
}

impl Poly1305 {
    /// Initialise from a 32-byte one-time key.
    /// Clamps `r` per RFC 8439 §2.5.1.
    pub fn new(key: &[u8; 32]) -> Self {
        // `r` is the low 16 bytes, little-endian, then clamped.
        let mut r_bytes = [0u8; 16];
        r_bytes.copy_from_slice(&key[..16]);
        // Clamp: certain bits must be zero.
        // Mask: 0x0ffffffc0ffffffc0ffffffc0fffffff
        r_bytes[3] &= 15;
        r_bytes[7] &= 15;
        r_bytes[11] &= 15;
        r_bytes[15] &= 15;
        r_bytes[4] &= 252;
        r_bytes[8] &= 252;
        r_bytes[12] &= 252;

        // Split clamped 128-bit r into 5 × 26-bit limbs.
        let r0 = u32::from_le_bytes([r_bytes[0], r_bytes[1], r_bytes[2], r_bytes[3]]) & 0x03ff_ffff;
        let r1 = (u32::from_le_bytes([r_bytes[3], r_bytes[4], r_bytes[5], r_bytes[6]]) >> 2)
            & 0x03ff_ff03;
        let r2 = (u32::from_le_bytes([r_bytes[6], r_bytes[7], r_bytes[8], r_bytes[9]]) >> 4)
            & 0x03ff_c0ff;
        let r3 = (u32::from_le_bytes([r_bytes[9], r_bytes[10], r_bytes[11], r_bytes[12]]) >> 6)
            & 0x03f0_3fff;
        let r4 = (u32::from_le_bytes([r_bytes[12], r_bytes[13], r_bytes[14], r_bytes[15]]) >> 8)
            & 0x000f_ffff;

        let s = [
            u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
            u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
            u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
            u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        ];

        Poly1305 {
            r: [r0, r1, r2, r3, r4],
            s,
            h: [0; 5],
            buf: [0; 16],
            buf_len: 0,
        }
    }

    /// Absorb `data`, buffering trailing bytes for the next call or
    /// `finalize()`.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = core::cmp::min(16 - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 16 {
                // SAFETY-ish: we own self.buf; splitting the &mut is safe here.
                let block = self.buf;
                self.block(&block, false);
                self.buf_len = 0;
            }
        }
        while data.len() >= 16 {
            let mut block = [0u8; 16];
            block.copy_from_slice(&data[..16]);
            self.block(&block, false);
            data = &data[16..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Finalise and return the 16-byte tag. Consumes the state.
    pub fn finalize(mut self) -> [u8; 16] {
        // Final partial block (if any): pad with 0x01 at byte `buf_len`,
        // zero the rest, and process with `final_block=true` so the high
        // bit is NOT added by `block`.
        if self.buf_len > 0 {
            let mut block = [0u8; 16];
            block[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            block[self.buf_len] = 0x01;
            self.block(&block, true);
        }

        // Fully carry + reduce the accumulator.
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        let mut c: u32;
        c = h1 >> 26; h1 &= 0x03ff_ffff; h2 += c;
        c = h2 >> 26; h2 &= 0x03ff_ffff; h3 += c;
        c = h3 >> 26; h3 &= 0x03ff_ffff; h4 += c;
        c = h4 >> 26; h4 &= 0x03ff_ffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x03ff_ffff; h1 += c;

        // Attempt h += -p (i.e. compute g = h - (2^130 - 5) = h + 5 - 2^130).
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26; g0 &= 0x03ff_ffff;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26; g1 &= 0x03ff_ffff;
        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26; g2 &= 0x03ff_ffff;
        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26; g3 &= 0x03ff_ffff;
        let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        // Select h if h < p, otherwise g. `mask` is all-ones when g4 >=
        // 0 (i.e. no borrow out of subtracting 2^130), meaning h ≥ p.
        let mask = (g4 >> 31).wrapping_sub(1);
        let inv_mask = !mask;
        h0 = (h0 & inv_mask) | (g0 & mask);
        h1 = (h1 & inv_mask) | (g1 & mask);
        h2 = (h2 & inv_mask) | (g2 & mask);
        h3 = (h3 & inv_mask) | (g3 & mask);
        h4 = (h4 & inv_mask) | (g4 & mask);

        // Pack 5×26-bit limbs into 4×32-bit words (h only needs 128 bits
        // after reduction).
        let h0_ = (h0) | (h1 << 26);
        let h1_ = (h1 >> 6) | (h2 << 20);
        let h2_ = (h2 >> 12) | (h3 << 14);
        let h3_ = (h3 >> 18) | (h4 << 8);

        // Final: tag = (h + s) mod 2^128.
        let mut tag = [0u8; 16];
        let t0 = h0_ as u64 + self.s[0] as u64;
        let t1 = h1_ as u64 + self.s[1] as u64 + (t0 >> 32);
        let t2 = h2_ as u64 + self.s[2] as u64 + (t1 >> 32);
        let t3 = h3_ as u64 + self.s[3] as u64 + (t2 >> 32);
        tag[0..4].copy_from_slice(&(t0 as u32).to_le_bytes());
        tag[4..8].copy_from_slice(&(t1 as u32).to_le_bytes());
        tag[8..12].copy_from_slice(&(t2 as u32).to_le_bytes());
        tag[12..16].copy_from_slice(&(t3 as u32).to_le_bytes());
        tag
    }

    /// Process one 16-byte block. If `final_block` is false, the implicit
    /// high-bit 1 is added (bit 128 of the block); if true, only the bytes
    /// written by the caller are used (for a padded short final block).
    fn block(&mut self, block: &[u8; 16], final_block: bool) {
        // Unpack block into 5 × 26-bit limbs, adding the "top bit" if not
        // a final (already-padded) block.
        let b0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]) & 0x03ff_ffff;
        let b1 = (u32::from_le_bytes([block[3], block[4], block[5], block[6]]) >> 2)
            & 0x03ff_ffff;
        let b2 = (u32::from_le_bytes([block[6], block[7], block[8], block[9]]) >> 4)
            & 0x03ff_ffff;
        let b3 = (u32::from_le_bytes([block[9], block[10], block[11], block[12]]) >> 6)
            & 0x03ff_ffff;
        let mut b4 = u32::from_le_bytes([block[12], block[13], block[14], block[15]]) >> 8;
        if !final_block {
            b4 |= 1 << 24;
        }

        // h += block
        let h0 = self.h[0].wrapping_add(b0);
        let h1 = self.h[1].wrapping_add(b1);
        let h2 = self.h[2].wrapping_add(b2);
        let h3 = self.h[3].wrapping_add(b3);
        let h4 = self.h[4].wrapping_add(b4);

        // h *= r
        let r0 = self.r[0] as u64;
        let r1 = self.r[1] as u64;
        let r2 = self.r[2] as u64;
        let r3 = self.r[3] as u64;
        let r4 = self.r[4] as u64;
        // Precompute 5×r_i for the wrap-around (since reduction mod 2^130-5).
        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let h0 = h0 as u64;
        let h1 = h1 as u64;
        let h2 = h2 as u64;
        let h3 = h3 as u64;
        let h4 = h4 as u64;

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        // Partial carry chain (still within u32 range after reduction).
        let mut c: u64;
        let mut h0 = (d0 & 0x03ff_ffff) as u32;
        c = d0 >> 26;
        let d1 = d1 + c;
        let mut h1 = (d1 & 0x03ff_ffff) as u32;
        c = d1 >> 26;
        let d2 = d2 + c;
        let mut h2 = (d2 & 0x03ff_ffff) as u32;
        c = d2 >> 26;
        let d3 = d3 + c;
        let h3 = (d3 & 0x03ff_ffff) as u32;
        c = d3 >> 26;
        let d4 = d4 + c;
        let h4 = (d4 & 0x03ff_ffff) as u32;
        c = d4 >> 26;
        h0 = h0.wrapping_add((c * 5) as u32);
        let carry = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 = h1.wrapping_add(carry);
        h2 = h2.wrapping_add(h1 >> 26);
        h1 &= 0x03ff_ffff;

        self.h = [h0, h1, h2, h3, h4];
    }
}

// ============================================================================
// AEAD_CHACHA20_POLY1305 (RFC 8439 §2.8)
// ============================================================================

/// One-shot AEAD encrypt. `data` is the plaintext on input and the
/// ciphertext on output (same length). `tag` receives the 16-byte
/// Poly1305 authentication tag.
///
/// `aad` is additional authenticated data — authenticated but not
/// encrypted.
pub fn chacha20poly1305_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
) -> [u8; 16] {
    // Step 1: derive one-time Poly1305 key from ChaCha20 block 0.
    let block0 = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&block0[..32]);

    // Step 2: encrypt plaintext with ChaCha20 counter starting at 1.
    chacha20_apply(key, 1, nonce, data);

    // Step 3: authenticate aad || pad16 || ciphertext || pad16 || lens.
    let mut mac = Poly1305::new(&poly_key);
    mac.update(aad);
    pad16(&mut mac, aad.len());
    mac.update(data);
    pad16(&mut mac, data.len());
    let mut lens = [0u8; 16];
    lens[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lens[8..16].copy_from_slice(&(data.len() as u64).to_le_bytes());
    mac.update(&lens);
    mac.finalize()
}

/// One-shot AEAD decrypt+verify. Returns `Ok(())` on tag match,
/// `Err(())` on mismatch (data is left unchanged in the error case —
/// the ChaCha20 decryption is deterministic and undoes itself, but we
/// short-circuit before touching plaintext).
pub fn chacha20poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), ()> {
    let block0 = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&block0[..32]);

    // Authenticate BEFORE decrypting.
    let mut mac = Poly1305::new(&poly_key);
    mac.update(aad);
    pad16(&mut mac, aad.len());
    mac.update(data);
    pad16(&mut mac, data.len());
    let mut lens = [0u8; 16];
    lens[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lens[8..16].copy_from_slice(&(data.len() as u64).to_le_bytes());
    mac.update(&lens);
    let expected = mac.finalize();

    if !ct_eq(&expected, tag) {
        return Err(());
    }
    chacha20_apply(key, 1, nonce, data);
    Ok(())
}

/// Pad Poly1305 input to a 16-byte boundary by absorbing zeros.
fn pad16(mac: &mut Poly1305, len: usize) {
    let rem = len & 15;
    if rem != 0 {
        let zeros = [0u8; 16];
        mac.update(&zeros[..16 - rem]);
    }
}

/// Constant-time byte-slice equality. Both slices must be the same
/// length; callers pass fixed-size tags so that's a static invariant.
fn ct_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ============================================================================
// Tests — RFC 8439 test vectors
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8439 §2.3.2
    #[test]
    fn chacha20_block_rfc8439() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00,
        ];
        let counter = 1u32;
        let expected: [u8; 64] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
            0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
            0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
            0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
            0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
            0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
            0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];
        let block = chacha20_block(&key, counter, &nonce);
        assert_eq!(block, expected);
    }

    // RFC 8439 §2.5.2 — Poly1305 test vector.
    #[test]
    fn poly1305_rfc8439() {
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        let expected: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
            0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
        ];
        let mut mac = Poly1305::new(&key);
        mac.update(msg);
        assert_eq!(mac.finalize(), expected);
    }

    // RFC 8439 §2.8.2 — ChaCha20-Poly1305 AEAD test vector.
    #[test]
    fn aead_rfc8439() {
        let plaintext: &[u8] = &[
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e,
            0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20,
            0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
            0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e,
            0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72,
            0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
            0x74, 0x2e,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let expected_ct: [u8; 114] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];
        let expected_tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        let mut data = [0u8; 114];
        data.copy_from_slice(plaintext);
        let tag = chacha20poly1305_seal(&key, &nonce, &aad, &mut data);
        assert_eq!(&data[..], &expected_ct[..]);
        assert_eq!(tag, expected_tag);

        // Round-trip.
        let opened = chacha20poly1305_open(&key, &nonce, &aad, &mut data, &tag);
        assert!(opened.is_ok());
        assert_eq!(&data[..], plaintext);
    }

    #[test]
    fn aead_open_rejects_tampered_tag() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = [];
        let mut data = [0u8; 32];
        let mut tag = chacha20poly1305_seal(&key, &nonce, &aad, &mut data);
        tag[0] ^= 0x01;
        let opened = chacha20poly1305_open(&key, &nonce, &aad, &mut data, &tag);
        assert!(opened.is_err());
    }
}
