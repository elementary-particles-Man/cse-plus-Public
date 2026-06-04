use crate::error::CseWireError;
use crate::wire::{CseWireDecode, CseWireEncode};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CseTlvV0 {
    pub tag: u16,
    pub len: u16,
    pub value: Vec<u8>,
}

impl CseWireEncode for CseTlvV0 {
    fn encoded_len(&self) -> usize {
        4 + self.value.len()
    }

    fn encode_into(&self, out: &mut [u8]) -> Result<usize, CseWireError> {
        if out.len() < self.encoded_len() {
            return Err(CseWireError::BufferTooSmall);
        }
        out[0..2].copy_from_slice(&self.tag.to_le_bytes());
        out[2..4].copy_from_slice(&self.len.to_le_bytes());
        out[4..4 + self.value.len()].copy_from_slice(&self.value);
        Ok(4 + self.value.len())
    }
}

impl CseWireDecode for CseTlvV0 {
    fn decode_from(input: &[u8]) -> Result<Self, CseWireError> {
        if input.len() < 4 {
            return Err(CseWireError::BufferTooSmall);
        }
        let tag = u16::from_le_bytes([input[0], input[1]]);
        let len = u16::from_le_bytes([input[2], input[3]]);
        if input.len() < 4 + len as usize {
            return Err(CseWireError::TruncatedPacket);
        }
        let mut value = vec![0u8; len as usize];
        value.copy_from_slice(&input[4..4 + len as usize]);
        Ok(CseTlvV0 { tag, len, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_roundtrip() {
        let tlv = CseTlvV0 {
            tag: 0x1234,
            len: 4,
            value: vec![1, 2, 3, 4],
        };
        let mut buf = [0u8; 10];
        let len = tlv.encode_into(&mut buf).unwrap();
        assert_eq!(len, 8);
        let decoded = CseTlvV0::decode_from(&buf[..len]).unwrap();
        assert_eq!(tlv, decoded);
    }
}
