use crate::types::{CseFailMode, CseProfileId, CseTxContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessSnapshot {
    pub mono: u64,
    pub source_system: u8,
    pub destination_system: u8,
    pub port: u16,
    pub flags: u16,
    pub len: u32,
    pub hash32: [u8; 32],
    pub ip: [u8; 16],
}

pub struct WitnessBridge;

impl WitnessBridge {
    pub fn create_context(
        snapshot: &WitnessSnapshot,
        profile: CseProfileId,
        key_id: [u8; 16],
        key_epoch: u64,
        policy_digest: [u8; 32],
    ) -> CseTxContext {
        let mut session_id = [0u8; 16];
        session_id[..8].copy_from_slice(&snapshot.mono.to_le_bytes());
        session_id[8..].copy_from_slice(&snapshot.mono.to_le_bytes());
        let mut actor_id_digest = [0u8; 16];
        actor_id_digest.copy_from_slice(&snapshot.hash32[..16]);

        CseTxContext {
            profile,
            facility_id_digest: [0xFA; 16],
            actor_id_digest,
            session_id,
            source_system: snapshot.source_system as u32,
            destination_system: snapshot.destination_system as u32,
            route_id: snapshot.port as u32,
            intent_tag: snapshot.flags,
            risk_tag: (snapshot.len / 1000) as u16,
            amount_bytes: Some(snapshot.hash32.to_vec()),
            beneficiary_bytes: Some(snapshot.ip.to_vec()),
            key_id,
            key_epoch,
            fail_mode: CseFailMode::Reject,
            policy_digest,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_creates_context() {
        let snapshot = WitnessSnapshot {
            mono: 42,
            source_system: 1,
            destination_system: 2,
            port: 8080,
            flags: 7,
            len: 1500,
            hash32: [3; 32],
            ip: [4; 16],
        };

        let ctx = WitnessBridge::create_context(
            &snapshot,
            CseProfileId::CsePlusStandard,
            [9; 16],
            1,
            [8; 32],
        );

        assert_eq!(ctx.source_system, 1);
        assert_eq!(ctx.destination_system, 2);
        assert_eq!(ctx.route_id, 8080);
        assert_eq!(ctx.intent_tag, 7);
        assert_eq!(ctx.risk_tag, 1);
    }
}
