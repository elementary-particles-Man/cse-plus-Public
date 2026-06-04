use crate::error::CseWireError;
use crate::wire::{CSE_TXN_CORE_LEN_V0, CseWireDecode, CseWireEncode};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CseTxnCoreV0 {
    pub actor_id_digest: [u8; 16],
    pub session_id: [u8; 16],
    pub source_system: u32,
    pub destination_system: u32,
    pub route_id: u32,
    pub intent_tag: u16,
    pub risk_tag: u16,
    pub seq_no: u64,
    pub timestamp_gmt_ms: u64,
    pub ttl_ms: u32,
    pub payload_digest: [u8; 32],
    pub before_state_digest: [u8; 32],
    pub amount_digest: [u8; 32],
    pub beneficiary_digest: [u8; 32],
    pub policy_digest: [u8; 32],
}

impl CseWireEncode for CseTxnCoreV0 {
    fn encoded_len(&self) -> usize {
        CSE_TXN_CORE_LEN_V0
    }

    fn encode_into(&self, out: &mut [u8]) -> Result<usize, CseWireError> {
        if out.len() < CSE_TXN_CORE_LEN_V0 {
            return Err(CseWireError::BufferTooSmall);
        }
        out[..CSE_TXN_CORE_LEN_V0].fill(0);
        out[0..16].copy_from_slice(&self.actor_id_digest);
        out[16..32].copy_from_slice(&self.session_id);
        out[32..36].copy_from_slice(&self.source_system.to_le_bytes());
        out[36..40].copy_from_slice(&self.destination_system.to_le_bytes());
        out[40..44].copy_from_slice(&self.route_id.to_le_bytes());
        out[44..46].copy_from_slice(&self.intent_tag.to_le_bytes());
        out[46..48].copy_from_slice(&self.risk_tag.to_le_bytes());
        out[48..56].copy_from_slice(&self.seq_no.to_le_bytes());
        out[56..64].copy_from_slice(&self.timestamp_gmt_ms.to_le_bytes());
        out[64..68].copy_from_slice(&self.ttl_ms.to_le_bytes());
        out[68..100].copy_from_slice(&self.payload_digest);
        out[100..132].copy_from_slice(&self.before_state_digest);
        out[132..164].copy_from_slice(&self.amount_digest);
        out[164..196].copy_from_slice(&self.beneficiary_digest);
        out[196..228].copy_from_slice(&self.policy_digest);
        // 228..256 extra reserved already zeroed
        Ok(CSE_TXN_CORE_LEN_V0)
    }
}

impl CseWireDecode for CseTxnCoreV0 {
    fn decode_from(input: &[u8]) -> Result<Self, CseWireError> {
        if input.len() < CSE_TXN_CORE_LEN_V0 {
            return Err(CseWireError::BufferTooSmall);
        }

        let mut actor_id_digest = [0u8; 16];
        actor_id_digest.copy_from_slice(&input[0..16]);

        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&input[16..32]);

        let source_system = u32::from_le_bytes([input[32], input[33], input[34], input[35]]);
        let destination_system = u32::from_le_bytes([input[36], input[37], input[38], input[39]]);
        let route_id = u32::from_le_bytes([input[40], input[41], input[42], input[43]]);
        let intent_tag = u16::from_le_bytes([input[44], input[45]]);
        let risk_tag = u16::from_le_bytes([input[46], input[47]]);
        let seq_no = u64::from_le_bytes([
            input[48], input[49], input[50], input[51], input[52], input[53], input[54], input[55],
        ]);
        let timestamp_gmt_ms = u64::from_le_bytes([
            input[56], input[57], input[58], input[59], input[60], input[61], input[62], input[63],
        ]);
        let ttl_ms = u32::from_le_bytes([input[64], input[65], input[66], input[67]]);

        let mut payload_digest = [0u8; 32];
        payload_digest.copy_from_slice(&input[68..100]);

        let mut before_state_digest = [0u8; 32];
        before_state_digest.copy_from_slice(&input[100..132]);

        let mut amount_digest = [0u8; 32];
        amount_digest.copy_from_slice(&input[132..164]);

        let mut beneficiary_digest = [0u8; 32];
        beneficiary_digest.copy_from_slice(&input[164..196]);

        let mut policy_digest = [0u8; 32];
        policy_digest.copy_from_slice(&input[196..228]);

        // Check the rest of padding (228..256)
        if input[228..256].iter().any(|&b| b != 0) {
            return Err(CseWireError::ReservedNonZero);
        }

        Ok(CseTxnCoreV0 {
            actor_id_digest,
            session_id,
            source_system,
            destination_system,
            route_id,
            intent_tag,
            risk_tag,
            seq_no,
            timestamp_gmt_ms,
            ttl_ms,
            payload_digest,
            before_state_digest,
            amount_digest,
            beneficiary_digest,
            policy_digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txn_core_roundtrip_v0() {
        let core = CseTxnCoreV0 {
            actor_id_digest: [0x11; 16],
            session_id: [0x22; 16],
            source_system: 1,
            destination_system: 2,
            route_id: 3,
            intent_tag: 4,
            risk_tag: 5,
            seq_no: 6,
            timestamp_gmt_ms: 123456789,
            ttl_ms: 30000,
            payload_digest: [0x33; 32],
            before_state_digest: [0x44; 32],
            amount_digest: [0x55; 32],
            beneficiary_digest: [0x66; 32],
            policy_digest: [0; 32],
        };

        let mut buf = [0u8; CSE_TXN_CORE_LEN_V0];
        core.encode_into(&mut buf).unwrap();

        let decoded = CseTxnCoreV0::decode_from(&buf).unwrap();
        assert_eq!(core, decoded);
    }
}
