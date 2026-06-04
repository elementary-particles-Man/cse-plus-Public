#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CseWireError {
    BufferTooSmall,
    InvalidMagic,
    UnsupportedVersion,
    InvalidPacketLength,
    InvalidSchema,
    InvalidProfile,
    ReservedNonZero,
    TruncatedPacket,
    InvalidKind,
    // D5 Replay Guard Errors
    ReplayDetected,
    SequenceRegression,
    NonceReuse,
    ExpiredPacket,
}

impl core::fmt::Display for CseWireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for CseWireError {}
