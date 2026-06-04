use crate::error::CseWireError;

pub trait CseWireDecode: Sized {
    fn decode_from(input: &[u8]) -> Result<Self, CseWireError>;
}
