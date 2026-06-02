use thiserror::Error;

/// Errors raised by the foreign Transport implementation. Host
/// platforms (Swift / Kotlin) build these from their own BLE / USB
/// stack errors; the Rust side never constructs them.
#[derive(Debug, Error, uniffi::Error)]
pub enum TronTransportError {
    #[error("transport disconnected: {reason}")]
    Disconnected { reason: String },
    #[error("transport timed out: {reason}")]
    Timeout { reason: String },
    #[error("transport I/O error: {reason}")]
    Io { reason: String },
}

/// One APDU round-trip response from the device.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TronExchangeResponse {
    /// SW1 SW2 as a big-endian u16. 0x9000 = success.
    pub status_word: u16,
    /// Response payload bytes excluding the trailing SW1 SW2.
    pub data: Vec<u8>,
}

/// Foreign callback interface implemented by the host platform.
/// Handles BLE GATT writes/notifies (Nano X), 5-byte BLE framing,
/// 153-byte MTU chunking, multi-packet response reassembly, and
/// the battery-service heartbeat that keeps the Ledger awake while
/// the user reads the on-device confirmation screen.
///
/// `exchange` receives a complete APDU (header + Lc + data, no Le)
/// and returns the reassembled response payload plus status word.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait TronLedgerTransport: Send + Sync {
    async fn exchange(&self, apdu: Vec<u8>) -> Result<TronExchangeResponse, TronTransportError>;
}
