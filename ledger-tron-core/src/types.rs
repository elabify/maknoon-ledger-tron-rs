/// Signature returned by `sign_transaction_*`. Tron signatures are
/// secp256k1 over the SHA-256 of the raw transaction protobuf.
/// Returned in (R, S, V) compact form: R(32) || S(32) || V(1), where
/// V is the 0/1 recovery id (NOT 27/28 — caller adds chain offsets
/// if needed).
#[derive(Debug, Clone, uniffi::Record)]
pub struct TronSignature {
    /// Raw 32-byte R component.
    pub r: Vec<u8>,
    /// Raw 32-byte S component.
    pub s: Vec<u8>,
    /// Recovery id: 0 or 1.
    pub v: u8,
}
