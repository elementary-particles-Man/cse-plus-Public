use crate::seal::CseSealEngine;
use tuff_cse_core::digest::CseDigest;
use tuff_cse_core::key_lifecycle::TuffKeyBundle;
use tuff_cse_core::profile::CseAlgTableV0;

pub struct RealKeyCseSealEngine {
    pub alg_table: CseAlgTableV0,
    pub keys: TuffKeyBundle,
}

impl CseSealEngine for RealKeyCseSealEngine {
    fn seal_v0(
        &self,
        packet_digest: &CseDigest,
        envelope_digest: &CseDigest,
    ) -> Result<[u8; 32], String> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&packet_digest.0);
        buf.extend_from_slice(&envelope_digest.0);
        buf.extend_from_slice(&self.alg_table.alg_table_digest);
        buf.extend_from_slice(&self.keys.component_a);

        let d = tuff_cse_core::digest::digest_canonical(b"standard-public-seal", &buf);
        Ok(d.0)
    }

    fn verify_v0(
        &self,
        packet_digest: &CseDigest,
        envelope_digest: &CseDigest,
        signature_material: &[u8; 32],
    ) -> Result<(), String> {
        let expected = self.seal_v0(packet_digest, envelope_digest)?;
        if signature_material == &expected {
            Ok(())
        } else {
            Err("Real KeyCSE signature mismatch".to_string())
        }
    }
}
