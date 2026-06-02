// ledger-tron-core: cross-platform Ledger Tron signing client.
//
// LedgerHQ does not maintain a Rust client for the Tron app; this
// crate hand-rolls the APDU encoding following the reference impl
// in `@ledgerhq/hw-app-trx` (TypeScript). UniFFI exposes the
// surface so iOS / Android share one implementation.

mod client;
mod error;
mod transport;
mod types;

pub use client::{LedgerTronClient, TronAddress};
pub use error::LedgerTronError;
pub use transport::{TronExchangeResponse, TronLedgerTransport, TronTransportError};
pub use types::TronSignature;

uniffi::setup_scaffolding!();
