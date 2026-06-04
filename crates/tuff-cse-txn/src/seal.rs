pub mod real_keycse;

use crate::error::CseWireError;
use crate::wire::CseWireEncode;
use crate::wire::binding::CseBindingV0;
use crate::wire::key_ref::CseKeyRefV0;
use crate::wire::txn_core::CseTxnCoreV0;
pub use real_keycse::RealKeyCseSealEngine;
use tuff_cse_core::digest::{
    CseDigest, DOMAIN_ENVELOPE_DIGEST_V0, DOMAIN_PACKET_DIGEST_V0, digest_canonical,
};

/// Parts required for envelope_digest calculation.
pub struct EnvelopeDigestPartsV0<'a> {
    pub key_ref: &'a CseKeyRefV0,
    pub txn_core: &'a CseTxnCoreV0,
}

pub fn envelope_digest_v0(parts: &EnvelopeDigestPartsV0) -> Result<CseDigest, CseWireError> {
    let mut buf = Vec::with_capacity(parts.key_ref.encoded_len() + parts.txn_core.encoded_len());

    // We encode into a temporary buffer to calculate digest.
    // Note: We MUST use the same encoding logic as the wire format.

    let mut key_ref_buf = vec![0u8; parts.key_ref.encoded_len()];
    parts.key_ref.encode_into(&mut key_ref_buf)?;
    buf.extend_from_slice(&key_ref_buf);

    let mut txn_core_buf = vec![0u8; parts.txn_core.encoded_len()];
    parts.txn_core.encode_into(&mut txn_core_buf)?;
    buf.extend_from_slice(&txn_core_buf);

    Ok(digest_canonical(DOMAIN_ENVELOPE_DIGEST_V0, &buf))
}

pub fn packet_digest_v0(
    envelope_digest: &CseDigest,
    binding: &CseBindingV0,
) -> Result<CseDigest, CseWireError> {
    let mut buf = Vec::with_capacity(32 + binding.encoded_len());
    buf.extend_from_slice(&envelope_digest.0);

    let mut binding_buf = vec![0u8; binding.encoded_len()];
    binding.encode_into(&mut binding_buf)?;
    buf.extend_from_slice(&binding_buf);

    Ok(digest_canonical(DOMAIN_PACKET_DIGEST_V0, &buf))
}

pub trait CseSealEngine {
    fn seal_v0(
        &self,
        packet_digest: &CseDigest,
        envelope_digest: &CseDigest,
    ) -> Result<[u8; 32], String>;

    fn verify_v0(
        &self,
        packet_digest: &CseDigest,
        envelope_digest: &CseDigest,
        signature_material: &[u8; 32],
    ) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::key_ref::CseKeyRefV0;
    use crate::wire::txn_core::CseTxnCoreV0;

    fn dummy_key_ref() -> CseKeyRefV0 {
        CseKeyRefV0 {
            key_id: [1; 16],
            key_epoch: 1,
            facility_id_digest: [2; 16],
            alg_suite_id: 1,
            alg_table_id: 1,
            policy_id: 1,
            reserved: [0; 64],
        }
    }

    fn dummy_txn_core() -> CseTxnCoreV0 {
        CseTxnCoreV0 {
            actor_id_digest: [3; 16],
            session_id: [4; 16],
            source_system: 1,
            destination_system: 2,
            route_id: 3,
            intent_tag: 101,
            risk_tag: 0,
            seq_no: 1,
            timestamp_gmt_ms: 1000,
            ttl_ms: 30000,
            payload_digest: [5; 32],
            before_state_digest: [0; 32],
            amount_digest: [0; 32],
            beneficiary_digest: [0; 32],
            policy_digest: [0; 32],
        }
    }

    #[test]
    fn envelope_digest_changes_on_intent_change() {
        let key_ref = dummy_key_ref();
        let mut txn_core = dummy_txn_core();

        txn_core.intent_tag = 101;
        let d1 = envelope_digest_v0(&EnvelopeDigestPartsV0 {
            key_ref: &key_ref,
            txn_core: &txn_core,
        })
        .unwrap();

        txn_core.intent_tag = 102;
        let d2 = envelope_digest_v0(&EnvelopeDigestPartsV0 {
            key_ref: &key_ref,
            txn_core: &txn_core,
        })
        .unwrap();

        assert_ne!(d1, d2);
    }
}
