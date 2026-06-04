use crate::error::CseWireError;
use crate::replay_journal::{CseReplayJournal, CseReplayJournalRecordV0};
use std::collections::{HashMap, HashSet};

pub struct CseReplayGuard {
    // scope_key -> max_seq_no
    seq_state: HashMap<Vec<u8>, u64>,
    // nonce_scope_key -> used
    nonce_state: HashSet<Vec<u8>>,
    // packet_digest -> used
    seen_digests: HashSet<[u8; 32]>,
}

impl Default for CseReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl CseReplayGuard {
    pub fn new() -> Self {
        Self {
            seq_state: HashMap::new(),
            nonce_state: HashSet::new(),
            seen_digests: HashSet::new(),
        }
    }

    pub fn check_and_update(
        &mut self,
        record: &CseReplayJournalRecordV0,
    ) -> Result<(), CseWireError> {
        // 1. Replay check by packet_digest
        if self.seen_digests.contains(&record.packet_digest) {
            return Err(CseWireError::ReplayDetected);
        }

        // 2. Sequence check
        let seq_scope = self.make_seq_scope(record);
        if self
            .seq_state
            .get(&seq_scope)
            .is_some_and(|&max_seq| record.seq_no <= max_seq)
        {
            return Err(CseWireError::SequenceRegression);
        }

        // 3. Nonce check
        let nonce_scope = self.make_nonce_scope(record);
        if self.nonce_state.contains(&nonce_scope) {
            return Err(CseWireError::NonceReuse);
        }

        // Update state
        self.seen_digests.insert(record.packet_digest);
        self.seq_state.insert(seq_scope, record.seq_no);
        self.nonce_state.insert(nonce_scope);

        Ok(())
    }

    fn make_seq_scope(&self, record: &CseReplayJournalRecordV0) -> Vec<u8> {
        let mut v = Vec::with_capacity(16 + 4 + 4 + 16 + 8);
        v.extend_from_slice(&record.facility_id_digest);
        v.extend_from_slice(&record.source_system.to_le_bytes());
        v.extend_from_slice(&record.destination_system.to_le_bytes());
        v.extend_from_slice(&record.key_id);
        v.extend_from_slice(&record.key_epoch.to_le_bytes());
        v
    }

    fn make_nonce_scope(&self, record: &CseReplayJournalRecordV0) -> Vec<u8> {
        let mut v = Vec::with_capacity(16 + 8 + 16 + 32);
        v.extend_from_slice(&record.key_id);
        v.extend_from_slice(&record.key_epoch.to_le_bytes());
        v.extend_from_slice(&record.tx_id);
        v.extend_from_slice(&record.nonce_digest);
        v
    }

    pub fn restore_from_journal(&mut self, journal: &CseReplayJournal) -> Result<(), CseWireError> {
        for record in &journal.records {
            let seq_scope = self.make_seq_scope(record);
            let nonce_scope = self.make_nonce_scope(record);

            self.seen_digests.insert(record.packet_digest);

            let max_seq = self.seq_state.entry(seq_scope).or_insert(0);
            if record.seq_no > *max_seq {
                *max_seq = record.seq_no;
            }

            self.nonce_state.insert(nonce_scope);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_record(
        seq: u64,
        tx: [u8; 16],
        packet: [u8; 32],
        nonce: [u8; 32],
    ) -> CseReplayJournalRecordV0 {
        CseReplayJournalRecordV0 {
            version: 0,
            record_len: 220,
            event_kind: 1,
            flags: 0,
            facility_id_digest: [1; 16],
            key_id: [2; 16],
            key_epoch: 1,
            source_system: 1,
            destination_system: 2,
            seq_no: seq,
            tx_id: tx,
            nonce_digest: nonce,
            packet_digest: packet,
            envelope_digest: [4; 32],
            decided_at_gmt_ms: 1000,
            decision_code: 0,
            error_code: 0,
            record_digest: [0; 32],
        }
    }

    #[test]
    fn replay_guard_rejects_same_packet_digest() {
        let mut guard = CseReplayGuard::new();
        let r1 = dummy_record(1, [0xAA; 16], [0x11; 32], [0x01; 32]);
        guard.check_and_update(&r1).unwrap();

        let r2 = dummy_record(2, [0xBB; 16], [0x11; 32], [0x02; 32]);
        assert_eq!(
            guard.check_and_update(&r2).unwrap_err(),
            CseWireError::ReplayDetected
        );
    }

    #[test]
    fn replay_guard_rejects_seq_regression() {
        let mut guard = CseReplayGuard::new();
        let r1 = dummy_record(10, [0xAA; 16], [0x11; 32], [0x01; 32]);
        guard.check_and_update(&r1).unwrap();

        let r2 = dummy_record(9, [0xBB; 16], [0x22; 32], [0x02; 32]);
        assert_eq!(
            guard.check_and_update(&r2).unwrap_err(),
            CseWireError::SequenceRegression
        );
    }

    #[test]
    fn replay_guard_rejects_nonce_reuse() {
        let mut guard = CseReplayGuard::new();
        let r1 = dummy_record(1, [0xAA; 16], [0x11; 32], [0x99; 32]);
        guard.check_and_update(&r1).unwrap();

        let r2 = dummy_record(2, [0xAA; 16], [0x22; 32], [0x99; 32]);
        assert_eq!(
            guard.check_and_update(&r2).unwrap_err(),
            CseWireError::NonceReuse
        );
    }

    #[test]
    fn replay_journal_rebuilds_state_after_restart() {
        let mut journal = CseReplayJournal::new();
        journal.append(dummy_record(10, [0xAA; 16], [0x11; 32], [0x01; 32]));
        journal.append(dummy_record(20, [0xBB; 16], [0x22; 32], [0x02; 32]));

        let mut guard = CseReplayGuard::new();
        guard.restore_from_journal(&journal).unwrap();

        // Check that state was restored: try a seq regression on the restored state
        let r3 = dummy_record(15, [0xCC; 16], [0x33; 32], [0x03; 32]);
        assert_eq!(
            guard.check_and_update(&r3).unwrap_err(),
            CseWireError::SequenceRegression
        );
    }
}
