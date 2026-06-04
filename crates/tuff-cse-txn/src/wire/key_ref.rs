use crate::error::CseWireError;
use crate::wire::{CSE_KEY_REF_LEN_V0, CseWireDecode, CseWireEncode};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CseKeyRefV0 {
    pub key_id: [u8; 16],
    pub key_epoch: u64,
    pub facility_id_digest: [u8; 16],
    pub alg_suite_id: u16,
    pub alg_table_id: u16,
    pub policy_id: u32,
    pub reserved: [u8; 64],
}

impl CseWireEncode for CseKeyRefV0 {
    fn encoded_len(&self) -> usize {
        CSE_KEY_REF_LEN_V0
    }

    fn encode_into(&self, out: &mut [u8]) -> Result<usize, CseWireError> {
        if out.len() < CSE_KEY_REF_LEN_V0 {
            return Err(CseWireError::BufferTooSmall);
        }
        out[..CSE_KEY_REF_LEN_V0].fill(0);
        out[0..16].copy_from_slice(&self.key_id);
        out[16..24].copy_from_slice(&self.key_epoch.to_le_bytes());
        out[24..40].copy_from_slice(&self.facility_id_digest);
        out[40..42].copy_from_slice(&self.alg_suite_id.to_le_bytes());
        out[42..44].copy_from_slice(&self.alg_table_id.to_le_bytes());
        out[44..48].copy_from_slice(&self.policy_id.to_le_bytes());
        // reserved is already filled with 0
        Ok(CSE_KEY_REF_LEN_V0)
    }
}

impl CseWireDecode for CseKeyRefV0 {
    fn decode_from(input: &[u8]) -> Result<Self, CseWireError> {
        if input.len() < CSE_KEY_REF_LEN_V0 {
            return Err(CseWireError::BufferTooSmall);
        }

        let mut key_id = [0u8; 16];
        key_id.copy_from_slice(&input[0..16]);

        let key_epoch = u64::from_le_bytes([
            input[16], input[17], input[18], input[19], input[20], input[21], input[22], input[23],
        ]);

        let mut facility_id_digest = [0u8; 16];
        facility_id_digest.copy_from_slice(&input[24..40]);

        let alg_suite_id = u16::from_le_bytes([input[40], input[41]]);
        let alg_table_id = u16::from_le_bytes([input[42], input[43]]);
        let policy_id = u32::from_le_bytes([input[44], input[45], input[46], input[47]]);

        let mut reserved = [0u8; 64];
        reserved.copy_from_slice(&input[48..112]);
        if reserved.iter().any(|&b| b != 0) {
            return Err(CseWireError::ReservedNonZero);
        }

        Ok(CseKeyRefV0 {
            key_id,
            key_epoch,
            facility_id_digest,
            alg_suite_id,
            alg_table_id,
            policy_id,
            reserved,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_ref_roundtrip_v0() {
        let key_ref = CseKeyRefV0 {
            key_id: [0x11; 16],
            key_epoch: 12345,
            facility_id_digest: [0x22; 16],
            alg_suite_id: 1,
            alg_table_id: 2,
            policy_id: 3,
            reserved: [0; 64],
        };

        let mut buf = [0u8; CSE_KEY_REF_LEN_V0];
        key_ref.encode_into(&mut buf).unwrap();

        let decoded = CseKeyRefV0::decode_from(&buf).unwrap();
        assert_eq!(key_ref, decoded);
    }

    #[test]
    fn key_ref_rejects_reserved_nonzero() {
        let mut buf = [0u8; CSE_KEY_REF_LEN_V0];
        buf[48] = 1;
        let res = CseKeyRefV0::decode_from(&buf);
        assert_eq!(res.unwrap_err(), CseWireError::ReservedNonZero);
    }
}
