use crate::digest::{CseDigest, digest_canonical};

pub struct CseAlgTableV0 {
    pub version: u16,
    pub alg_table_id: u16,
    pub institution_id_digest: [u8; 16],
    pub key_epoch: u64,
    pub id_permutation: [u8; 256],
    pub min_allowed_suite: u16,
    pub flags: u32,
    pub alg_table_digest: [u8; 32],
}

impl CseAlgTableV0 {
    pub fn new_mock(institution_id: [u8; 16], epoch: u64) -> Self {
        let mut id_permutation = [0u8; 256];
        for (i, item) in id_permutation.iter_mut().enumerate() {
            *item = i as u8;
        }
        // Simple deterministic swap for mock
        for i in 0..256 {
            let swap_idx = (i + epoch as usize) % 256;
            id_permutation.swap(i, swap_idx);
        }

        let mut table = Self {
            version: 0,
            alg_table_id: 1,
            institution_id_digest: institution_id,
            key_epoch: epoch,
            id_permutation,
            min_allowed_suite: 0,
            flags: 0,
            alg_table_digest: [0; 32],
        };
        table.alg_table_digest = table.calculate_digest().0;
        table
    }

    pub fn calculate_digest(&self) -> CseDigest {
        let mut buf = Vec::with_capacity(256 + 64);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.alg_table_id.to_le_bytes());
        buf.extend_from_slice(&self.institution_id_digest);
        buf.extend_from_slice(&self.key_epoch.to_le_bytes());
        buf.extend_from_slice(&self.id_permutation);
        buf.extend_from_slice(&self.min_allowed_suite.to_le_bytes());
        buf.extend_from_slice(&self.flags.to_le_bytes());
        digest_canonical(b"cse-plus-alg-table-v0", &buf)
    }

    pub fn lookup_internal_id(&self, wire_suite_id: u16) -> Result<u8, String> {
        if wire_suite_id >= 256 {
            return Err("wire_suite_id out of range (0..255)".to_string());
        }
        Ok(self.id_permutation[wire_suite_id as usize])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alg_table_digest_changes_on_permutation_change() {
        let mut table = CseAlgTableV0::new_mock([1; 16], 1);
        let d1 = table.calculate_digest();

        table.id_permutation.swap(0, 1);
        let d2 = table.calculate_digest();

        assert_ne!(d1, d2);
    }

    #[test]
    fn alg_table_lookup_works() {
        let table = CseAlgTableV0::new_mock([1; 16], 1);
        let internal_id = table.lookup_internal_id(10).unwrap();
        // Just verify it's a valid byte
        let _ = internal_id;
    }
}
