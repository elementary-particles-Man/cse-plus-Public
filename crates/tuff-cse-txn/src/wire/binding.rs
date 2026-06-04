use crate::error::CseWireError;
use crate::wire::{CSE_BINDING_LEN_V0, CseWireDecode, CseWireEncode};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CseBindingV0 {
    pub logical_anchor_lba: u64,
    pub stream_index: u64,
    pub keycse_nonce: [u8; 16],
    pub keycse_wire_key: [u8; 32],
    pub reserved: [u8; 64],
}

impl CseWireEncode for CseBindingV0 {
    fn encoded_len(&self) -> usize {
        CSE_BINDING_LEN_V0
    }

    fn encode_into(&self, out: &mut [u8]) -> Result<usize, CseWireError> {
        if out.len() < CSE_BINDING_LEN_V0 {
            return Err(CseWireError::BufferTooSmall);
        }
        out[..CSE_BINDING_LEN_V0].fill(0);
        out[0..8].copy_from_slice(&self.logical_anchor_lba.to_le_bytes());
        out[8..16].copy_from_slice(&self.stream_index.to_le_bytes());
        out[16..32].copy_from_slice(&self.keycse_nonce);
        out[32..64].copy_from_slice(&self.keycse_wire_key);
        // reserved 64..128 already zeroed
        Ok(CSE_BINDING_LEN_V0)
    }
}

impl CseWireDecode for CseBindingV0 {
    fn decode_from(input: &[u8]) -> Result<Self, CseWireError> {
        if input.len() < CSE_BINDING_LEN_V0 {
            return Err(CseWireError::BufferTooSmall);
        }

        let logical_anchor_lba = u64::from_le_bytes([
            input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
        ]);
        let stream_index = u64::from_le_bytes([
            input[8], input[9], input[10], input[11], input[12], input[13], input[14], input[15],
        ]);

        let mut keycse_nonce = [0u8; 16];
        keycse_nonce.copy_from_slice(&input[16..32]);

        let mut keycse_wire_key = [0u8; 32];
        keycse_wire_key.copy_from_slice(&input[32..64]);

        let mut reserved = [0u8; 64];
        reserved.copy_from_slice(&input[64..128]);
        if reserved.iter().any(|&b| b != 0) {
            return Err(CseWireError::ReservedNonZero);
        }

        Ok(CseBindingV0 {
            logical_anchor_lba,
            stream_index,
            keycse_nonce,
            keycse_wire_key,
            reserved,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_roundtrip_v0() {
        let binding = CseBindingV0 {
            logical_anchor_lba: 1000,
            stream_index: 5,
            keycse_nonce: [0x77; 16],
            keycse_wire_key: [0x88; 32],
            reserved: [0; 64],
        };

        let mut buf = [0u8; CSE_BINDING_LEN_V0];
        binding.encode_into(&mut buf).unwrap();

        let decoded = CseBindingV0::decode_from(&buf).unwrap();
        assert_eq!(binding, decoded);
    }
}
