// Software "TRON Signed Message" (TIP-191) sign + keyless verify, ported 1:1
// from the Bitcoin message core (ledger-btc-core/src/message.rs). Shared by
// iOS, Android, and the Ledger flow so every wallet produces byte-identical
// output and interoperates with TronWeb / TronLink (signMessageV2 /
// verifyMessageV2) and Trust Wallet Core's TronMessageSigner.
//
// TIP-191: digest = keccak256("\x19" + "TRON Signed Message:\n" + len + msg),
// signed with recoverable secp256k1; the signature is the 0x-hex r||s||v with
// v in {27,28} (web3 form). The signature binds to the signer's base58check
// T-address, which is what `tron_verify_message` recovers and checks.
//
// Software wallets derive the key (Trust Wallet Core HDWallet at
// m/44'/195'/<account>'/0/0) and hand the raw 32-byte secret here. The Ledger
// client signs on-device and calls `signed_message_from_parts` to assemble the
// same shape (recovering the address host-side).

use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

use crate::address::{keccak256, tron_base58check, tron_raw_address};

/// A TIP-191 signed message: the bound T-address + the 0x-hex r||s||v signature.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TronSignedMessage {
    /// base58check T-address the signature is bound to (what a verifier checks).
    pub address: String,
    /// 0x-hex 65-byte signature (r || s || v), v in {27,28}.
    pub signature: String,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TronMsgError {
    #[error("invalid secret key")]
    InvalidKey,
    #[error("signing failed")]
    SigningFailed,
    #[error("could not derive the signer address")]
    AddressFailed,
}

/// TIP-191 prefixed digest.
fn tip191_digest(message: &str) -> [u8; 32] {
    let m = message.as_bytes();
    let mut v = format!("\u{0019}TRON Signed Message:\n{}", m.len()).into_bytes();
    v.extend_from_slice(m);
    keccak256(&v)
}

/// Sign `message` with the raw 32-byte secret key in the TIP-191 format.
#[uniffi::export]
pub fn tron_sign_message(
    secret_key: Vec<u8>,
    message: String,
) -> Result<TronSignedMessage, TronMsgError> {
    let sk = SecretKey::from_slice(&secret_key).map_err(|_| TronMsgError::InvalidKey)?;
    let secp = Secp256k1::new();
    let msg = Message::from_digest(tip191_digest(&message));
    let recsig = secp.sign_ecdsa_recoverable(&msg, &sk);
    let (recid, compact) = recsig.serialize_compact();
    // Recover (so the bound address comes from the same path verify uses) and
    // assemble the 0x-hex r||s||v with v in {27,28}.
    let v = 27u8 + (recid.to_i32() as u8);
    signed_message_from_compact(&compact, v, tip191_digest(&message))
}

/// Verify a TIP-191 signature: recover the signer address and compare
/// (case-insensitively trimmed) to `address`. Keyless.
#[uniffi::export]
pub fn tron_verify_message(address: String, message: String, signature: String) -> bool {
    match recover_address(&message, &signature) {
        Some(recovered) => recovered == address.trim(),
        None => false,
    }
}

/// Assemble a `TronSignedMessage` from device-returned signature parts: the
/// 64-byte compact r||s, the recovery id (0/1), and the message. Recovers the
/// address from the TIP-191 digest. Used by the Ledger client.
pub(crate) fn signed_message_from_parts(
    message: &str,
    r: &[u8],
    s: &[u8],
    recid: u8,
) -> Result<TronSignedMessage, TronMsgError> {
    if r.len() != 32 || s.len() != 32 {
        return Err(TronMsgError::SigningFailed);
    }
    let mut compact = [0u8; 64];
    compact[..32].copy_from_slice(r);
    compact[32..].copy_from_slice(s);
    let v = 27u8 + (recid & 0x01);
    signed_message_from_compact(&compact, v, tip191_digest(message))
}

fn signed_message_from_compact(
    compact: &[u8; 64],
    v: u8,
    digest: [u8; 32],
) -> Result<TronSignedMessage, TronMsgError> {
    let address = recover_from_compact(compact, v, digest).ok_or(TronMsgError::AddressFailed)?;
    let mut sig = compact.to_vec();
    sig.push(v);
    Ok(TronSignedMessage {
        address,
        signature: format!("0x{}", hex::encode(sig)),
    })
}

/// Recover the base58check address from a 0x-hex 65-byte signature + message.
fn recover_address(message: &str, signature: &str) -> Option<String> {
    let trimmed = signature.trim();
    let hexs = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let raw = hex::decode(hexs).ok()?;
    if raw.len() != 65 {
        return None;
    }
    let mut compact = [0u8; 64];
    compact.copy_from_slice(&raw[..64]);
    recover_from_compact(&compact, raw[64], tip191_digest(message))
}

fn recover_from_compact(compact: &[u8; 64], v: u8, digest: [u8; 32]) -> Option<String> {
    // Accept web3 v (27/28) and the bare recovery id (0/1).
    let recid_i = if v >= 27 { (v - 27) as i32 } else { v as i32 } & 0x01;
    let recid = RecoveryId::from_i32(recid_i).ok()?;
    let recsig = RecoverableSignature::from_compact(compact, recid).ok()?;
    let secp = Secp256k1::new();
    let pk: PublicKey = secp.recover_ecdsa(&Message::from_digest(digest), &recsig).ok()?;
    let raw = tron_raw_address(&pk.serialize_uncompressed())?;
    Some(tron_base58check(&raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed secret key -> deterministic address + round-trip.
    fn sk_bytes() -> Vec<u8> {
        vec![0x11u8; 32]
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let signed = tron_sign_message(sk_bytes(), "hello tron".into()).unwrap();
        assert!(signed.address.starts_with('T'));
        assert!(signed.signature.starts_with("0x"));
        assert_eq!(signed.signature.len(), 2 + 130); // 0x + 65 bytes hex
        assert!(tron_verify_message(
            signed.address.clone(),
            "hello tron".into(),
            signed.signature.clone()
        ));
        // Tampered message must fail.
        assert!(!tron_verify_message(
            signed.address,
            "hello tro".into(),
            signed.signature
        ));
    }

    #[test]
    fn verify_rejects_garbage() {
        assert!(!tron_verify_message(
            "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC".into(),
            "x".into(),
            "0xdeadbeef".into()
        ));
    }

    // Cross-platform known-answer vector (the same corpus iOS + Android assert),
    // cross-checked against WalletCore's TronMessageSigner in tests/kat_gen.rs.
    const KAT: &str = include_str!("../test-vectors/tron-message-signing-kat.json");

    #[test]
    fn tron_kat_corpus_matches() {
        let v: serde_json::Value = serde_json::from_str(KAT).unwrap();
        let t = &v["tron"];
        let sk = hex::decode(t["secretKeyHex"].as_str().unwrap()).unwrap();
        let msg = t["message"].as_str().unwrap().to_string();
        let want_addr = t["expectedAddress"].as_str().unwrap();
        let want_sig = t["expectedSignature"].as_str().unwrap();

        let signed = tron_sign_message(sk, msg.clone()).unwrap();
        assert_eq!(signed.address, want_addr);
        assert_eq!(signed.signature, want_sig);
        assert!(tron_verify_message(want_addr.to_string(), msg, want_sig.to_string()));
    }
}
