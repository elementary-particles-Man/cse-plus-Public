use crate::error::CseWireError;
use crate::wire::{CSE_HEADER_LEN_V0, CSE_MAGIC, CseWireDecode, CseWireEncode};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CseWireHeaderV0 {
    pub magic: [u8; 4],
    pub version: u8,
    pub profile: u8,
    pub packet_kind: u8,
    pub flags: u8,
    pub header_len: u16,
    pub packet_len: u16,
    pub schema_id: u16,
    pub reserved: u16,
    pub tx_id: [u8; 16],
}

impl CseWireEncode for CseWireHeaderV0 {
    fn encoded_len(&self) -> usize {
        CSE_HEADER_LEN_V0
    }

    fn encode_into(&self, out: &mut [u8]) -> Result<usize, CseWireError> {
        if out.len() < CSE_HEADER_LEN_V0 {
            return Err(CseWireError::BufferTooSmall);
        }
        out[..CSE_HEADER_LEN_V0].fill(0);
        out[0..4].copy_from_slice(&self.magic);
        out[4] = self.version;
        out[5] = self.profile;
        out[6] = self.packet_kind;
        out[7] = self.flags;
        out[8..10].copy_from_slice(&self.header_len.to_le_bytes());
        out[10..12].copy_from_slice(&self.packet_len.to_le_bytes());
        out[12..14].copy_from_slice(&self.schema_id.to_le_bytes());
        out[14..16].copy_from_slice(&self.reserved.to_le_bytes());
        out[16..32].copy_from_slice(&self.tx_id);
        Ok(CSE_HEADER_LEN_V0)
    }
}

impl CseWireDecode for CseWireHeaderV0 {
    fn decode_from(input: &[u8]) -> Result<Self, CseWireError> {
        if input.len() < CSE_HEADER_LEN_V0 {
            return Err(CseWireError::BufferTooSmall);
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&input[0..4]);
        if magic != CSE_MAGIC {
            return Err(CseWireError::InvalidMagic);
        }

        let version = input[4];
        if version != 0 {
            return Err(CseWireError::UnsupportedVersion);
        }

        let profile = input[5];
        let packet_kind = input[6];
        if packet_kind == 0 || packet_kind > 3 {
            return Err(CseWireError::InvalidKind);
        }
        let flags = input[7];
        let header_len = u16::from_le_bytes([input[8], input[9]]);
        let packet_len = u16::from_le_bytes([input[10], input[11]]);
        let schema_id = u16::from_le_bytes([input[12], input[13]]);
        let reserved = u16::from_le_bytes([input[14], input[15]]);

        if header_len as usize != CSE_HEADER_LEN_V0 {
            return Err(CseWireError::InvalidPacketLength);
        }
        if packet_len > 1024 {
            return Err(CseWireError::InvalidPacketLength);
        }
        if reserved != 0 {
            return Err(CseWireError::ReservedNonZero);
        }

        let mut tx_id = [0u8; 16];
        tx_id.copy_from_slice(&input[16..32]);

        Ok(CseWireHeaderV0 {
            magic,
            version,
            profile,
            packet_kind,
            flags,
            header_len,
            packet_len,
            schema_id,
            reserved,
            tx_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::CSE_HEADER_LEN_V0;

    #[test]
    fn header_roundtrip_v0() {
        let header = CseWireHeaderV0 {
            magic: CSE_MAGIC,
            version: 0,
            profile: 1,
            packet_kind: 1, // SessionOpen
            flags: 3,
            header_len: CSE_HEADER_LEN_V0 as u16,
            packet_len: 100,
            schema_id: 4,
            reserved: 0,
            tx_id: [0xAA; 16],
        };

        let mut buf = [0u8; CSE_HEADER_LEN_V0];
        header.encode_into(&mut buf).unwrap();

        let decoded = CseWireHeaderV0::decode_from(&buf).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn header_rejects_invalid_magic() {
        let mut buf = [0u8; CSE_HEADER_LEN_V0];
        buf[0..4].copy_from_slice(b"BAD!");
        let res = CseWireHeaderV0::decode_from(&buf);
        assert_eq!(res.unwrap_err(), CseWireError::InvalidMagic);
    }

    #[test]
    fn header_rejects_reserved_nonzero() {
        let header = CseWireHeaderV0 {
            magic: CSE_MAGIC,
            version: 0,
            profile: 1,
            packet_kind: 2,
            flags: 3,
            header_len: CSE_HEADER_LEN_V0 as u16,
            packet_len: 100,
            schema_id: 4,
            reserved: 1,
            tx_id: [0; 16],
        };

        let mut buf = [0u8; CSE_HEADER_LEN_V0];
        header.encode_into(&mut buf).unwrap();

        let res = CseWireHeaderV0::decode_from(&buf);
        assert_eq!(res.unwrap_err(), CseWireError::ReservedNonZero);
    }

    #[test]
    fn header_rejects_packet_len_over_1024() {
        let header = CseWireHeaderV0 {
            magic: CSE_MAGIC,
            version: 0,
            profile: 1,
            packet_kind: 2,
            flags: 3,
            header_len: CSE_HEADER_LEN_V0 as u16,
            packet_len: 1025,
            schema_id: 4,
            reserved: 0,
            tx_id: [0; 16],
        };

        let mut buf = [0u8; CSE_HEADER_LEN_V0];
        header.encode_into(&mut buf).unwrap();

        let res = CseWireHeaderV0::decode_from(&buf);
        assert_eq!(res.unwrap_err(), CseWireError::InvalidPacketLength);
    }

    #[test]
    fn header_rejects_invalid_kind() {
        let mut buf = [0u8; CSE_HEADER_LEN_V0];
        let header = CseWireHeaderV0 {
            magic: CSE_MAGIC,
            version: 0,
            profile: 1,
            packet_kind: 99, // Invalid
            flags: 0,
            header_len: CSE_HEADER_LEN_V0 as u16,
            packet_len: 100,
            schema_id: 0,
            reserved: 0,
            tx_id: [0; 16],
        };
        header.encode_into(&mut buf).unwrap();
        let res = CseWireHeaderV0::decode_from(&buf);
        assert_eq!(res.unwrap_err(), CseWireError::InvalidKind);
    }
}
