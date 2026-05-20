// Small byte reader used by ClientHello (and any future) parsers.
//
// Crate-private: every TLS parser in this module shares the same
// length-prefixed vector / fixed-width integer helpers, so they live
// in one place rather than getting copy-pasted per message type.

use super::ParseError;

pub(super) struct Reader<'a> {
    pub(super) buf: &'a [u8],
    pub(super) pos: usize,
}

impl<'a> Reader<'a> {
    pub(super) fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub(super) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub(super) fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub(super) fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        if self.remaining() < n {
            return Err(ParseError::Truncated);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub(super) fn read_u16(&mut self) -> Result<u16, ParseError> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(super) fn read_u32(&mut self) -> Result<u32, ParseError> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a length-prefixed vector where the length is a u8.
    pub(super) fn read_vector_u8(&mut self) -> Result<&'a [u8], ParseError> {
        if self.remaining() < 1 {
            return Err(ParseError::Truncated);
        }
        let len = self.buf[self.pos] as usize;
        self.pos += 1;
        self.read_bytes(len)
    }

    /// Read a length-prefixed vector where the length is a big-endian u16.
    pub(super) fn read_vector_u16(&mut self) -> Result<&'a [u8], ParseError> {
        let len = self.read_u16()? as usize;
        self.read_bytes(len)
    }
}
