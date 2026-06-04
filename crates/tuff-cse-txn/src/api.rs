use crate::seal::{CseSealEngine, EnvelopeDigestPartsV0, envelope_digest_v0, packet_digest_v0};
use crate::types::{
    CseApplyDecision, CseFailMode, CseProfileId, CseTxContext, NetworkResult, VerifiedTransaction,
};
use crate::wire::binding::CseBindingV0;
use crate::wire::key_ref::CseKeyRefV0;
use crate::wire::packet::CseTxnOnePacketV0;
use crate::wire::seal::CseSealV0;
use crate::wire::txn_core::CseTxnCoreV0;
use crate::wire::{
    CSE_HEADER_LEN_V0, CSE_MAGIC, CSE_TXN_ONE_FIXED_LEN_V0, CseWireDecode, CseWireEncode,
    CseWireHeaderV0,
};
use tuff_cse_core::digest::payload_digest_v0;

pub struct CsePreSendOutput {
    pub tx_id: [u8; 16],
    pub packet: Vec<u8>,
    pub packet_digest: [u8; 32],
    pub envelope_digest: [u8; 32],
    pub mode: CseFailMode,
}

pub fn cse_pre_send(
    ctx: CseTxContext,
    payload: &[u8],
    before_state: Option<&[u8]>,
    seal_engine: &dyn CseSealEngine,
) -> Result<CsePreSendOutput, String> {
    let tx_id = [0x77; 16];

    let p_digest = payload_digest_v0(payload);
    let b_digest = before_state.map(payload_digest_v0).unwrap_or_default();

    let key_ref = CseKeyRefV0 {
        key_id: ctx.key_id,
        key_epoch: ctx.key_epoch,
        facility_id_digest: ctx.facility_id_digest,
        alg_suite_id: 1,
        alg_table_id: 1,
        policy_id: 1,
        reserved: [0; 64],
    };

    let txn_core = CseTxnCoreV0 {
        actor_id_digest: ctx.actor_id_digest,
        session_id: ctx.session_id,
        source_system: ctx.source_system,
        destination_system: ctx.destination_system,
        route_id: ctx.route_id,
        intent_tag: ctx.intent_tag,
        risk_tag: ctx.risk_tag,
        seq_no: 1,
        timestamp_gmt_ms: 1000,
        ttl_ms: 60000,
        payload_digest: p_digest.0,
        before_state_digest: b_digest.0,
        amount_digest: [0; 32],
        beneficiary_digest: [0; 32],
        policy_digest: ctx.policy_digest,
    };

    let e_digest = envelope_digest_v0(&EnvelopeDigestPartsV0 {
        key_ref: &key_ref,
        txn_core: &txn_core,
    })
    .map_err(|e| e.to_string())?;

    let binding = CseBindingV0 {
        logical_anchor_lba: 0,
        stream_index: 0,
        keycse_nonce: [0x88; 16],
        keycse_wire_key: [0; 32], // Zeroized in wire
        reserved: [0; 64],
    };

    let pack_digest = packet_digest_v0(&e_digest, &binding).map_err(|e| e.to_string())?;

    let signature = seal_engine.seal_v0(&pack_digest, &e_digest)?;

    let header = CseWireHeaderV0 {
        magic: CSE_MAGIC,
        version: 0,
        profile: ctx.profile as u8,
        packet_kind: 1, // TxnOne
        flags: 0,
        header_len: CSE_HEADER_LEN_V0 as u16,
        packet_len: CSE_TXN_ONE_FIXED_LEN_V0 as u16,
        schema_id: 0,
        reserved: 0,
        tx_id,
    };

    let packet_struct = CseTxnOnePacketV0 {
        header,
        key_ref,
        txn_core,
        binding,
        seal: CseSealV0 {
            packet_digest: pack_digest.0,
            signature_material: signature,
        },
    };

    let mut buf = vec![0u8; CSE_TXN_ONE_FIXED_LEN_V0];
    packet_struct
        .encode_into(&mut buf)
        .map_err(|e| e.to_string())?;

    Ok(CsePreSendOutput {
        tx_id,
        packet: buf,
        packet_digest: pack_digest.0,
        envelope_digest: e_digest.0,
        mode: ctx.fail_mode,
    })
}

pub fn cse_pre_recv(
    raw_packet: &[u8],
    seal_engine: &dyn CseSealEngine,
) -> Result<VerifiedTransaction, String> {
    let packet = CseTxnOnePacketV0::decode_from(raw_packet).map_err(|e| e.to_string())?;

    let e_digest = envelope_digest_v0(&EnvelopeDigestPartsV0 {
        key_ref: &packet.key_ref,
        txn_core: &packet.txn_core,
    })
    .map_err(|e| e.to_string())?;

    let pack_digest = packet_digest_v0(&e_digest, &packet.binding).map_err(|e| e.to_string())?;

    if pack_digest.0 != packet.seal.packet_digest {
        return Err("Packet digest mismatch".to_string());
    }

    seal_engine.verify_v0(&pack_digest, &e_digest, &packet.seal.signature_material)?;

    Ok(VerifiedTransaction {
        tx_id: packet.header.tx_id,
        profile: match packet.header.profile {
            0 => CseProfileId::Minimal,
            1 => CseProfileId::CsePlusEmergency,
            2 => CseProfileId::CsePlusStandard,
            3 => CseProfileId::CsePlusHighAssurance,
            4 => CseProfileId::AtmOnePacket,
            _ => return Err("Invalid profile ID".to_string()),
        },
        intent_tag: packet.txn_core.intent_tag,
        payload_digest: packet.txn_core.payload_digest,
        before_state_digest: packet.txn_core.before_state_digest,
        key_id: packet.key_ref.key_id,
        key_epoch: packet.key_ref.key_epoch,
    })
}

pub fn cse_pre_apply(
    verified: &VerifiedTransaction,
    current_state: &[u8],
) -> Result<CseApplyDecision, String> {
    let current_digest = payload_digest_v0(current_state);
    if current_digest.0 == verified.before_state_digest {
        Ok(CseApplyDecision::Allow)
    } else {
        // In real impl, we'd check fail_mode from context (not in VerifiedTransaction yet, but for now simple)
        Ok(CseApplyDecision::Reject(
            "Before state mismatch".to_string(),
        ))
    }
}

pub fn cse_post_send(tx_id: [u8; 16], _network_result: &NetworkResult) -> Result<(), String> {
    // Log minimal info
    println!("CSE PostSend: tx_id={:02x?}", tx_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::RealKeyCseSealEngine;
    use tuff_cse_core::key_lifecycle::TuffKeyBundle;
    use tuff_cse_core::profile::CseAlgTableV0;

    fn dummy_engine() -> RealKeyCseSealEngine {
        let alg_table = CseAlgTableV0::new_mock([1; 16], 1);
        let keys = TuffKeyBundle::from_components(&[1; 32], &[2; 32], &[3; 32]);
        RealKeyCseSealEngine { alg_table, keys }
    }

    fn dummy_context() -> CseTxContext {
        CseTxContext {
            profile: CseProfileId::CsePlusStandard,
            facility_id_digest: [1; 16],
            actor_id_digest: [2; 16],
            session_id: [3; 16],
            source_system: 1,
            destination_system: 2,
            route_id: 10,
            intent_tag: 101,
            risk_tag: 0,
            amount_bytes: None,
            beneficiary_bytes: None,
            key_id: [4; 16],
            key_epoch: 1,
            fail_mode: CseFailMode::Reject,
            policy_digest: [0x66; 32],
        }
    }

    #[test]
    fn pre_send_recv_roundtrip() {
        let engine = dummy_engine();
        let ctx = dummy_context();
        let payload = b"hello finance";

        let output = cse_pre_send(ctx.clone(), payload, None, &engine).unwrap();
        let verified = cse_pre_recv(&output.packet, &engine).unwrap();

        assert_eq!(verified.tx_id, output.tx_id);
        assert_eq!(verified.payload_digest, payload_digest_v0(payload).0);
    }

    #[test]
    fn pre_apply_matches_state() {
        let state = b"ledger v1";
        let digest = payload_digest_v0(state);
        let verified = VerifiedTransaction {
            tx_id: [0; 16],
            profile: CseProfileId::CsePlusStandard,
            intent_tag: 101,
            payload_digest: [0; 32],
            before_state_digest: digest.0,
            key_id: [0; 16],
            key_epoch: 1,
        };

        match cse_pre_apply(&verified, state).unwrap() {
            CseApplyDecision::Allow => (),
            _ => panic!("Should allow"),
        }
    }
}
