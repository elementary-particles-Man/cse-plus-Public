use crate::error::CseWireError;
use crate::wire::binding::CseBindingV0;
use crate::wire::key_ref::CseKeyRefV0;
use crate::wire::seal::CseSealV0;
use crate::wire::txn_core::CseTxnCoreV0;
use crate::wire::{
    CSE_BINDING_LEN_V0, CSE_HEADER_LEN_V0, CSE_KEY_REF_LEN_V0, CSE_SEAL_LEN_V0,
    CSE_TXN_CORE_LEN_V0, CSE_TXN_ONE_FIXED_LEN_V0, CseWireDecode, CseWireEncode, CseWireHeaderV0,
};
use static_assertions::const_assert_eq;

const_assert_eq!(
    CSE_HEADER_LEN_V0
        + CSE_KEY_REF_LEN_V0
        + CSE_TXN_CORE_LEN_V0
        + CSE_BINDING_LEN_V0
        + CSE_SEAL_LEN_V0,
    CSE_TXN_ONE_FIXED_LEN_V0
);

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CseTxnOnePacketV0 {
    pub header: CseWireHeaderV0,
    pub key_ref: CseKeyRefV0,
    pub txn_core: CseTxnCoreV0,
    pub binding: CseBindingV0,
    pub seal: CseSealV0,
}

impl CseWireEncode for CseTxnOnePacketV0 {
    fn encoded_len(&self) -> usize {
        CSE_TXN_ONE_FIXED_LEN_V0
    }

    fn encode_into(&self, out: &mut [u8]) -> Result<usize, CseWireError> {
        if out.len() < CSE_TXN_ONE_FIXED_LEN_V0 {
            return Err(CseWireError::BufferTooSmall);
        }

        let mut offset = 0;
        offset += self.header.encode_into(&mut out[offset..])?;
        offset += self.key_ref.encode_into(&mut out[offset..])?;
        offset += self.txn_core.encode_into(&mut out[offset..])?;
        offset += self.binding.encode_into(&mut out[offset..])?;
        offset += self.seal.encode_into(&mut out[offset..])?;

        Ok(offset)
    }
}

impl CseWireDecode for CseTxnOnePacketV0 {
    fn decode_from(input: &[u8]) -> Result<Self, CseWireError> {
        if input.len() < CSE_TXN_ONE_FIXED_LEN_V0 {
            return Err(CseWireError::TruncatedPacket);
        }

        let mut offset = 0;
        let header = CseWireHeaderV0::decode_from(&input[offset..])?;
        offset += CSE_HEADER_LEN_V0;

        let key_ref = CseKeyRefV0::decode_from(&input[offset..])?;
        offset += CSE_KEY_REF_LEN_V0;

        let txn_core = CseTxnCoreV0::decode_from(&input[offset..])?;
        offset += CSE_TXN_CORE_LEN_V0;

        let binding = CseBindingV0::decode_from(&input[offset..])?;
        offset += CSE_BINDING_LEN_V0;

        let seal = CseSealV0::decode_from(&input[offset..])?;
        // offset += CSE_SEAL_LEN_V0;

        Ok(CseTxnOnePacketV0 {
            header,
            key_ref,
            txn_core,
            binding,
            seal,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::CSE_MAGIC;

    #[test]
    fn txn_one_packet_fixed_len_is_592() {
        assert_eq!(CSE_TXN_ONE_FIXED_LEN_V0, 592);
    }

    #[test]
    fn txn_one_roundtrip_v0() {
        let packet = CseTxnOnePacketV0 {
            header: CseWireHeaderV0 {
                magic: CSE_MAGIC,
                version: 0,
                profile: 1,
                packet_kind: 1, // TxnOne
                flags: 0,
                header_len: CSE_HEADER_LEN_V0 as u16,
                packet_len: CSE_TXN_ONE_FIXED_LEN_V0 as u16,
                schema_id: 0,
                reserved: 0,
                tx_id: [0x11; 16],
            },
            key_ref: CseKeyRefV0 {
                key_id: [0x22; 16],
                key_epoch: 1,
                facility_id_digest: [0x33; 16],
                alg_suite_id: 1,
                alg_table_id: 1,
                policy_id: 1,
                reserved: [0; 64],
            },
            txn_core: CseTxnCoreV0 {
                actor_id_digest: [0x44; 16],
                session_id: [0x55; 16],
                source_system: 1,
                destination_system: 2,
                route_id: 3,
                intent_tag: 101,
                risk_tag: 0,
                seq_no: 1,
                timestamp_gmt_ms: 1716465600000,
                ttl_ms: 60000,
                payload_digest: [0x66; 32],
                before_state_digest: [0; 32],
                amount_digest: [0; 32],
                beneficiary_digest: [0; 32],
                policy_digest: [0; 32],
            },
            binding: CseBindingV0 {
                logical_anchor_lba: 0,
                stream_index: 0,
                keycse_nonce: [0x77; 16],
                keycse_wire_key: [0x88; 32],
                reserved: [0; 64],
            },
            seal: CseSealV0 {
                packet_digest: [0x99; 32],
                signature_material: [0xAA; 32],
            },
        };

        let mut buf = [0u8; 1024];
        let len = packet.encode_into(&mut buf).unwrap();
        assert_eq!(len, 592);

        let decoded = CseTxnOnePacketV0::decode_from(&buf[..len]).unwrap();
        assert_eq!(packet, decoded);
    }
}
