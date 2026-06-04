//! Public reference HTTP adapter surface.

use tuff_cse_txn::api::{cse_pre_recv, cse_pre_send};
use tuff_cse_txn::seal::RealKeyCseSealEngine;

pub fn adapter_name() -> &'static str {
    "cse-plus-public-http"
}

pub fn roundtrip_packet(
    ctx: tuff_cse_txn::CseTxContext,
    payload: &[u8],
    engine: &RealKeyCseSealEngine,
) -> Result<[u8; 16], String> {
    let pre = cse_pre_send(ctx, payload, None, engine)?;
    let verified = cse_pre_recv(&pre.packet, engine)?;
    Ok(verified.tx_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tuff_cse_core::key_lifecycle::TuffKeyBundle;
    use tuff_cse_core::profile::CseAlgTableV0;
    use tuff_cse_txn::{CseFailMode, CseProfileId, CseTxContext};

    fn engine() -> RealKeyCseSealEngine {
        let alg_table = CseAlgTableV0::new_mock([1; 16], 1);
        let keys = TuffKeyBundle::from_components(&[1; 32], &[2; 32], &[3; 32]);
        RealKeyCseSealEngine { alg_table, keys }
    }

    fn context() -> CseTxContext {
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
    fn adapter_roundtrip_works() {
        let tx_id = roundtrip_packet(context(), b"payload", &engine()).unwrap();
        assert_eq!(tx_id, [0x77; 16]);
    }
}
