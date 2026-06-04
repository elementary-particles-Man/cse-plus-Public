use crate::error::CseWireError;

pub trait CseWireEncode {
    fn encoded_len(&self) -> usize;
    fn encode_into(&self, out: &mut [u8]) -> Result<usize, CseWireError>;
}
