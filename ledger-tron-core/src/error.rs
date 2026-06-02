use thiserror::Error;

use crate::transport::TronTransportError;

/// Errors surfaced from the public API. Designed for clean UniFFI
/// marshalling: each variant carries a `reason` string so Swift /
/// Kotlin callers can show or log a useful message without
/// inspecting the variant.
#[derive(Debug, Error, uniffi::Error)]
pub enum LedgerTronError {
    /// The injected Transport failed (BLE disconnect, timeout,
    /// unplugged, etc.). Host platform supplies the description.
    #[error("transport error: {reason}")]
    Transport { reason: String },

    /// Tron app returned a non-success status word. 0x6985 maps to
    /// `UserCanceled`; everything else lands here with the SW byte
    /// preserved for diagnostics.
    #[error("device rejected (status 0x{status_word:04X}): {reason}")]
    DeviceRejected { status_word: u16, reason: String },

    /// Derivation path argument couldn't be parsed.
    #[error("invalid derivation path: {reason}")]
    InvalidPath { reason: String },

    /// Transaction protobuf argument was malformed or empty.
    #[error("invalid transaction: {reason}")]
    InvalidTransaction { reason: String },

    /// Anything unexpected in the protocol exchange that isn't
    /// covered by the more specific variants above.
    #[error("protocol error: {reason}")]
    Protocol { reason: String },

    /// User pressed reject on the device (status word 0x6985).
    #[error("user canceled on device")]
    UserCanceled,
}

impl From<TronTransportError> for LedgerTronError {
    fn from(err: TronTransportError) -> Self {
        LedgerTronError::Transport {
            reason: err.to_string(),
        }
    }
}

#[allow(dead_code)]
impl LedgerTronError {
    pub(crate) fn protocol(msg: impl Into<String>) -> Self {
        LedgerTronError::Protocol { reason: msg.into() }
    }

    pub(crate) fn invalid_path(msg: impl Into<String>) -> Self {
        LedgerTronError::InvalidPath { reason: msg.into() }
    }

    pub(crate) fn invalid_tx(msg: impl Into<String>) -> Self {
        LedgerTronError::InvalidTransaction { reason: msg.into() }
    }

    pub(crate) fn from_status(status_word: u16, command_label: &str) -> Self {
        match status_word {
            0x6985 => LedgerTronError::UserCanceled,
            sw => LedgerTronError::DeviceRejected {
                status_word: sw,
                reason: format!("{command_label}: device returned 0x{sw:04X}"),
            },
        }
    }
}
