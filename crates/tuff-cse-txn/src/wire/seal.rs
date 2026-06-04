use crate::error::CseWireError;
use crate::wire::{CSE_SEAL_LEN_V0, CseWireDecode, CseWireEncode};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CseSealV0 {
    pub packet_digest: [u8; 32],
    pub signature_material: [u8; 32],
}

impl CseWireEncode for CseSealV0 {
    fn encoded_len(&self) -> usize {
        CSE_SEAL_LEN_V0
    }

    fn encode_into(&self, out: &mut [u8]) -> Result<usize, CseWireError> {
        if out.len() < CSE_SEAL_LEN_V0 {
            return Err(CseWireError::BufferTooSmall);
        }
        out[..CSE_SEAL_LEN_V0].fill(0);
        out[0..32].copy_from_slice(&self.packet_digest);
        out[32..64].copy_from_slice(&self.signature_material);
        Ok(CSE_SEAL_LEN_V0)
    }
}

impl CseWireDecode for CseSealV0 {
    fn decode_from(input: &[u8]) -> Result<Self, CseWireError> {
        if input.len() < CSE_SEAL_LEN_V0 {
            return Err(CseWireError::BufferTooSmall);
        }

        let mut packet_digest = [0u8; 32];
        packet_digest.copy_from_slice(&input[0..32]);

        let mut signature_material = [0u8; 32];
        signature_material.copy_from_slice(&input[32..64]);

        Ok(CseSealV0 {
            packet_digest,
            signature_material,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip_v0() {
        let seal = CseSealV0 {
            packet_digest: [0x99; 32],
            signature_material: [0xAA; 32],
        };

        let mut buf = [0u8; CSE_SEAL_LEN_V0];
        seal.encode_into(&mut buf).unwrap();

        let decoded = CseSealV0::decode_from(&buf).unwrap();
        assert_eq!(seal, decoded);
    }
}
