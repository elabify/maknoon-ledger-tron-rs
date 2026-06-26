// Shared Tron address primitives, used by both the Ledger client
// (device pubkey -> address) and the message-signing path (recovered
// pubkey -> address). One implementation so the two can never drift.

use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// Keccak-256. Tron uses the same hash as Ethereum for address
/// derivation; only the prefix byte (0x41) differs.
pub(crate) fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(input);
    h.finalize().into()
}

/// 21-byte raw Tron address `[0x41, keccak256(pubkey_xy)[12..]]` from a
/// 65-byte uncompressed secp256k1 pubkey (0x04 || X || Y). None if the
/// input is not a well-formed uncompressed key.
pub(crate) fn tron_raw_address(pubkey: &[u8]) -> Option<Vec<u8>> {
    if pubkey.len() != 65 || pubkey[0] != 0x04 {
        return None;
    }
    let hash = keccak256(&pubkey[1..]);
    let mut raw = Vec::with_capacity(21);
    raw.push(0x41);
    raw.extend_from_slice(&hash[12..]);
    Some(raw)
}

/// Base58check encode the 21-byte raw address (double-SHA-256 checksum,
/// identical to Bitcoin's base58check). Yields the T-prefixed string.
pub(crate) fn tron_base58check(raw: &[u8]) -> String {
    let h1 = Sha256::digest(raw);
    let h2 = Sha256::digest(h1);
    let mut buf = Vec::with_capacity(raw.len() + 4);
    buf.extend_from_slice(raw);
    buf.extend_from_slice(&h2[..4]);
    bs58::encode(&buf).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak256_empty_input() {
        assert_eq!(
            hex::encode(keccak256(&[])),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn keccak256_abc() {
        assert_eq!(
            hex::encode(keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    #[test]
    fn tron_address_pipeline_round_trips() {
        let pubkey = hex::decode(
            "04eb6c2ef2b08c1c91dbe0e4e60ba00b3b9b6f8cb4d6e0d2a8b6f0b9b3b0c0d0e0\
             5c5d5e5f5050515253545556575859ABCDEF0123456789ABCDEF0123456789AB"
                .replace(['\n', ' '], ""),
        )
        .unwrap();
        let raw = tron_raw_address(&pubkey).unwrap();
        assert_eq!(raw.len(), 21);
        assert_eq!(raw[0], 0x41);
        let addr = tron_base58check(&raw);
        assert!(addr.starts_with('T'));
        assert_eq!(addr.len(), 34);
    }
}
