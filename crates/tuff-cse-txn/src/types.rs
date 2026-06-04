use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CseProfileId {
    Minimal = 0,
    CsePlusEmergency = 1,
    CsePlusStandard = 2,
    CsePlusHighAssurance = 3,
    AtmOnePacket = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CseFailMode {
    AuditOnly = 0,
    Warning = 1,
    Hold = 2,
    Reject = 3,
    FailClosed = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CseTxContext {
    pub profile: CseProfileId,
    pub facility_id_digest: [u8; 16],
    pub actor_id_digest: [u8; 16],
    pub session_id: [u8; 16],
    pub source_system: u32,
    pub destination_system: u32,
    pub route_id: u32,
    pub intent_tag: u16,
    pub risk_tag: u16,
    pub amount_bytes: Option<Vec<u8>>,
    pub beneficiary_bytes: Option<Vec<u8>>,
    pub key_id: [u8; 16],
    pub key_epoch: u64,
    pub fail_mode: CseFailMode,
    pub policy_digest: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct VerifiedTransaction {
    pub tx_id: [u8; 16],
    pub profile: CseProfileId,
    pub intent_tag: u16,
    pub payload_digest: [u8; 32],
    pub before_state_digest: [u8; 32],
    pub key_id: [u8; 16],
    pub key_epoch: u64,
}

#[derive(Debug, Clone)]
pub enum CseApplyDecision {
    Allow,
    Hold(String),
    Reject(String),
}

#[derive(Debug, Clone)]
pub enum NetworkResult {
    Success,
    Timeout,
    TransportError(String),
}
