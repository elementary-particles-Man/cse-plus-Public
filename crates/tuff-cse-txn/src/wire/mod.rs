pub mod binding;
pub mod decode;
pub mod encode;
pub mod header;
pub mod key_ref;
pub mod packet;
pub mod seal;
pub mod tlv;
pub mod txn_core;

pub use decode::CseWireDecode;
pub use encode::CseWireEncode;
pub use header::CseWireHeaderV0;

pub const CSE_MAGIC: [u8; 4] = *b"CST0";
pub const CSE_WIRE_VERSION_V0: u8 = 0;
pub const CSE_MAX_PACKET_LEN: usize = 1024;

pub const PACKET_KIND_SESSION_OPEN: u8 = 1;
pub const PACKET_KIND_TXN_ONE: u8 = 2;
pub const PACKET_KIND_TXN_END: u8 = 3;

pub const CSE_HEADER_LEN_V0: usize = 32;
pub const CSE_KEY_REF_LEN_V0: usize = 112;
pub const CSE_TXN_CORE_LEN_V0: usize = 256;
pub const CSE_BINDING_LEN_V0: usize = 128;
pub const CSE_SEAL_LEN_V0: usize = 64;
pub const CSE_TXN_ONE_FIXED_LEN_V0: usize = 592;
