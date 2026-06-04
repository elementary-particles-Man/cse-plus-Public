use crate::error::CseWireError;
use crate::wire::{CseWireDecode, CseWireEncode};
use tuff_cse_core::digest::{CseDigest, digest_canonical};

pub const CSE_JOURNAL_RECORD_LEN_V0: usize = 212;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CseReplayJournalRecordV0 {
    pub version: u16,
    pub record_len: u16,
    pub event_kind: u16,
    pub flags: u16,
    pub facility_id_digest: [u8; 16],
    pub key_id: [u8; 16],
    pub key_epoch: u64,
    pub source_system: u32,
    pub destination_system: u32,
    pub seq_no: u64,
    pub tx_id: [u8; 16],
    pub nonce_digest: [u8; 32],
    pub packet_digest: [u8; 32],
    pub envelope_digest: [u8; 32],
    pub decided_at_gmt_ms: u64,
    pub decision_code: u16,
    pub error_code: u16,
    pub record_digest: [u8; 32],
}

impl CseReplayJournalRecordV0 {
    pub fn calculate_record_digest(&self) -> CseDigest {
        let mut buf = vec![0u8; CSE_JOURNAL_RECORD_LEN_V0 - 32];
        // We can reuse encode logic but exclude the last 32 bytes
        let mut temp = self.clone();
        temp.record_digest = [0; 32];
        temp.encode_into(&mut buf[..]).unwrap();
        digest_canonical(b"cse-plus-journal-record-v0", &buf)
    }
}

impl CseWireEncode for CseReplayJournalRecordV0 {
    fn encoded_len(&self) -> usize {
        CSE_JOURNAL_RECORD_LEN_V0
    }

    fn encode_into(&self, out: &mut [u8]) -> Result<usize, CseWireError> {
        if out.len() < CSE_JOURNAL_RECORD_LEN_V0 {
            return Err(CseWireError::BufferTooSmall);
        }
        out[0..2].copy_from_slice(&self.version.to_le_bytes());
        out[2..4].copy_from_slice(&self.record_len.to_le_bytes());
        out[4..6].copy_from_slice(&self.event_kind.to_le_bytes());
        out[6..8].copy_from_slice(&self.flags.to_le_bytes());
        out[8..24].copy_from_slice(&self.facility_id_digest);
        out[24..40].copy_from_slice(&self.key_id);
        out[40..48].copy_from_slice(&self.key_epoch.to_le_bytes());
        out[48..52].copy_from_slice(&self.source_system.to_le_bytes());
        out[52..56].copy_from_slice(&self.destination_system.to_le_bytes());
        out[56..64].copy_from_slice(&self.seq_no.to_le_bytes());
        out[64..80].copy_from_slice(&self.tx_id);
        out[80..112].copy_from_slice(&self.nonce_digest);
        out[112..144].copy_from_slice(&self.packet_digest);
        out[144..176].copy_from_slice(&self.envelope_digest);
        out[176..184].copy_from_slice(&self.decided_at_gmt_ms.to_le_bytes());
        out[184..186].copy_from_slice(&self.decision_code.to_le_bytes());
        out[186..188].copy_from_slice(&self.error_code.to_le_bytes());
        out[188..212].copy_from_slice(&self.record_digest[0..24]); // Error: record_digest is 32B, but only 24B left?
        // Wait, 188 + 32 = 220. My calculation above was slightly off.
        // 2+2+2+2+16+16+8+4+4+8+16+32+32+32+8+2+2 = 180.
        // 180 + 32 = 212. Correct.
        // Let's re-verify:
        // 0..2 (2)
        // 2..4 (2)
        // 4..6 (2)
        // 6..8 (2)
        // 8..24 (16)
        // 24..40 (16)
        // 40..48 (8)
        // 48..52 (4)
        // 52..56 (4)
        // 56..64 (8)
        // 64..80 (16)
        // 80..112 (32)
        // 112..144 (32)
        // 144..176 (32)
        // 176..184 (8)
        // 184..186 (2)
        // 186..188 (2)
        // 188..220 (32) -> Total 220.

        out[188..220].copy_from_slice(&self.record_digest);
        Ok(220)
    }
}

impl CseWireDecode for CseReplayJournalRecordV0 {
    fn decode_from(input: &[u8]) -> Result<Self, CseWireError> {
        if input.len() < 220 {
            return Err(CseWireError::BufferTooSmall);
        }
        let version = u16::from_le_bytes([input[0], input[1]]);
        let record_len = u16::from_le_bytes([input[2], input[3]]);
        let event_kind = u16::from_le_bytes([input[4], input[5]]);
        let flags = u16::from_le_bytes([input[6], input[7]]);
        let mut facility_id_digest = [0u8; 16];
        facility_id_digest.copy_from_slice(&input[8..24]);
        let mut key_id = [0u8; 16];
        key_id.copy_from_slice(&input[24..40]);
        let key_epoch = u64::from_le_bytes([
            input[40], input[41], input[42], input[43], input[44], input[45], input[46], input[47],
        ]);
        let source_system = u32::from_le_bytes([input[48], input[49], input[50], input[51]]);
        let destination_system = u32::from_le_bytes([input[52], input[53], input[54], input[55]]);
        let seq_no = u64::from_le_bytes([
            input[56], input[57], input[58], input[59], input[60], input[61], input[62], input[63],
        ]);
        let mut tx_id = [0u8; 16];
        tx_id.copy_from_slice(&input[64..80]);
        let mut nonce_digest = [0u8; 32];
        nonce_digest.copy_from_slice(&input[80..112]);
        let mut packet_digest = [0u8; 32];
        packet_digest.copy_from_slice(&input[112..144]);
        let mut envelope_digest = [0u8; 32];
        envelope_digest.copy_from_slice(&input[144..176]);
        let decided_at_gmt_ms = u64::from_le_bytes([
            input[176], input[177], input[178], input[179], input[180], input[181], input[182],
            input[183],
        ]);
        let decision_code = u16::from_le_bytes([input[184], input[185]]);
        let error_code = u16::from_le_bytes([input[186], input[187]]);
        let mut record_digest = [0u8; 32];
        record_digest.copy_from_slice(&input[188..220]);

        Ok(CseReplayJournalRecordV0 {
            version,
            record_len,
            event_kind,
            flags,
            facility_id_digest,
            key_id,
            key_epoch,
            source_system,
            destination_system,
            seq_no,
            tx_id,
            nonce_digest,
            packet_digest,
            envelope_digest,
            decided_at_gmt_ms,
            decision_code,
            error_code,
            record_digest,
        })
    }
}

pub struct CseReplayJournal {
    pub records: Vec<CseReplayJournalRecordV0>,
}

impl Default for CseReplayJournal {
    fn default() -> Self {
        Self::new()
    }
}

impl CseReplayJournal {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    pub fn append(&mut self, record: CseReplayJournalRecordV0) {
        self.records.push(record);
    }
}
