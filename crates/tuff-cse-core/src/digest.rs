use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct CseDigest(pub [u8; 32]);

impl core::fmt::Debug for CseDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "CseDigest({:02x}{:02x}{:02x}{:02x}..)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

pub const DOMAIN_PAYLOAD_DIGEST_V0: &[u8] = b"cse-plus-payload-v0";
pub const DOMAIN_ENVELOPE_DIGEST_V0: &[u8] = b"cse-plus-envelope-v0";
pub const DOMAIN_PACKET_DIGEST_V0: &[u8] = b"cse-plus-packet-v0";
pub const DOMAIN_SEAL_V0: &[u8] = b"cse-plus-seal-v0";

/// Canonical digest with domain separation and length prefixing.
pub fn digest_canonical(domain: &[u8], data: &[u8]) -> CseDigest {
    let mut hasher = Sha256::new();
    // Domain
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    // Data
    hasher.update((data.len() as u64).to_le_bytes());
    hasher.update(data);

    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    CseDigest(out)
}

pub fn payload_digest_v0(payload: &[u8]) -> CseDigest {
    digest_canonical(DOMAIN_PAYLOAD_DIGEST_V0, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_digest_changes_on_one_byte_change() {
        let payload1 = b"hello world";
        let payload2 = b"jello world";
        let d1 = payload_digest_v0(payload1);
        let d2 = payload_digest_v0(payload2);
        assert_ne!(d1, d2);
    }

    #[test]
    fn domain_separation_yields_different_digests() {
        let data = b"common data";
        let d1 = digest_canonical(b"domain1", data);
        let d2 = digest_canonical(b"domain2", data);
        assert_ne!(d1, d2);
    }
}
