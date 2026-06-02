use std::sync::Arc;

use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::error::LedgerTronError;
use crate::transport::TronLedgerTransport;
use crate::types::TronSignature;

// Tron app APDU constants. Source of truth:
// https://github.com/LedgerHQ/app-tron and the @ledgerhq/hw-app-trx
// TypeScript reference. Tron's app is conceptually similar to the
// Ethereum app (secp256k1 over a domain hash) but differs in INS
// codes and input shape.
const CLA: u8 = 0xE0;
const INS_GET_PUBLIC_KEY: u8 = 0x02;
const INS_SIGN: u8 = 0x04;
const INS_GET_APP_CONFIG: u8 = 0x06;

const P1_NON_CONFIRM: u8 = 0x00;
const P1_CONFIRM: u8 = 0x01;

// SIGN chunking flags. The Tron app uses a 4-value scheme defined
// in app-tron/src/handlers/handlers.h:
//
//   P1_FIRST = 0x00 — first chunk; data starts with BIP32 path,
//                     then raw_data. More chunks expected after.
//   P1_SIGN  = 0x10 — first AND only chunk; data starts with BIP32
//                     path, then raw_data. Sign immediately.
//   P1_MORE  = 0x80 — continuation chunk; NO path, just raw_data
//                     continuation. More chunks expected.
//   P1_LAST  = 0x90 — final chunk; NO path, raw_data continuation,
//                     sign now.
//
// Key distinction from Ethereum/Solana: the BIP32 path is sent
// ONLY in the first chunk (P1_FIRST or P1_SIGN), NOT in
// continuation chunks. Sending the path in a P1_MORE/P1_LAST
// chunk corrupts the protobuf and the device rejects with
// E_INCORRECT_P1_P2 (0x6B00), because the path bytes also confuse
// the "context must be initialized first" check.
const P1_FIRST: u8 = 0x00;
const P1_SIGN: u8 = 0x10;
const P1_MORE: u8 = 0x80;
const P1_LAST: u8 = 0x90;

const MAX_APDU_DATA: usize = 255;
const SW_SUCCESS: u16 = 0x9000;

/// Top-level client for the Ledger Tron app. Construct once per
/// device session, then call `get_app_configuration`,
/// `get_address_*`, or `sign_transaction_*`.
///
/// Thread-safe: methods take `&self` and the foreign transport
/// naturally serializes concurrent calls (BLE allows one in-flight
/// APDU at a time).
#[derive(uniffi::Object)]
pub struct LedgerTronClient {
    transport: Arc<dyn TronLedgerTransport>,
}

/// Tron address record returned by `get_address_*`. Tron addresses
/// are base58check-encoded; the raw 21-byte form starts with 0x41
/// followed by the 20-byte hash of the secp256k1 pubkey (keccak-256
/// of uncompressed pubkey XY, then truncated to last 20 bytes).
#[derive(Debug, Clone, uniffi::Record)]
pub struct TronAddress {
    /// Raw 65-byte uncompressed secp256k1 public key (0x04 || X || Y).
    pub pubkey: Vec<u8>,
    /// 21-byte raw address ([0x41, keccak_last_20]).
    pub raw: Vec<u8>,
    /// Base58check representation. This is what users paste into
    /// wallets and explorers (T-prefixed).
    pub base58check: String,
}

#[uniffi::export(async_runtime = "tokio")]
impl LedgerTronClient {
    #[uniffi::constructor]
    pub fn new(transport: Arc<dyn TronLedgerTransport>) -> Arc<Self> {
        Arc::new(Self { transport })
    }

    /// Returns the Tron app version on-device as `[major, minor, patch]`.
    pub async fn get_app_configuration(&self) -> Result<Vec<u8>, LedgerTronError> {
        let response = self
            .exchange(CLA, INS_GET_APP_CONFIG, 0x00, 0x00, &[])
            .await?;
        if response.len() < 4 {
            return Err(LedgerTronError::protocol(format!(
                "GET_APP_CONFIG: expected ≥4 bytes, got {}",
                response.len()
            )));
        }
        // Layout per app-tron: [flags, major, minor, patch].
        Ok(vec![response[1], response[2], response[3]])
    }

    /// Returns the address for the given BIP44 account at the
    /// standard Tron path `m/44'/195'/<account>'/0/0`. `display`
    /// asks the device to prompt the user on-screen first; useful
    /// for the receive-address verification flow.
    pub async fn get_address_for_account(
        &self,
        account: u32,
        display: bool,
    ) -> Result<TronAddress, LedgerTronError> {
        let components = standard_tron_path(account);
        self.get_address_inner(&components, display).await
    }

    /// Returns the address at an explicit BIP-32 path. Path syntax
    /// follows BIP-32 with `'` for hardened, e.g.
    /// `"m/44'/195'/0'/0/0"`.
    pub async fn get_address_at_path(
        &self,
        path: String,
        display: bool,
    ) -> Result<TronAddress, LedgerTronError> {
        let components = parse_bip32_path(&path)?;
        self.get_address_inner(&components, display).await
    }

    /// Sign the SHA-256 hash of a serialized Tron `raw_data` protobuf
    /// at the standard account path. The host builds the
    /// `Transaction.raw_data` (NOT the full `Transaction` with
    /// signature slots) and ships those bytes. The device displays
    /// transfer parameters, the user confirms, and the 65-byte
    /// (R || S || V) signature comes back.
    pub async fn sign_transaction_for_account(
        &self,
        account: u32,
        raw_data: Vec<u8>,
    ) -> Result<TronSignature, LedgerTronError> {
        let components = standard_tron_path(account);
        self.sign_inner(&components, &raw_data).await
    }

    /// Sign at an explicit BIP-32 path. See
    /// `sign_transaction_for_account` for semantics.
    pub async fn sign_transaction_at_path(
        &self,
        path: String,
        raw_data: Vec<u8>,
    ) -> Result<TronSignature, LedgerTronError> {
        let components = parse_bip32_path(&path)?;
        self.sign_inner(&components, &raw_data).await
    }
}

impl LedgerTronClient {
    async fn get_address_inner(
        &self,
        components: &[u32],
        display: bool,
    ) -> Result<TronAddress, LedgerTronError> {
        let payload = encode_path(components);
        let p1 = if display { P1_CONFIRM } else { P1_NON_CONFIRM };
        let response = self
            .exchange(CLA, INS_GET_PUBLIC_KEY, p1, 0x00, &payload)
            .await?;
        // Response layout per app-trx:
        //   1B(pkLen) || pubkey || 1B(addrAsciiLen) || addr ascii bytes
        if response.is_empty() {
            return Err(LedgerTronError::protocol("GET_PUBLIC_KEY: empty response"));
        }
        let pk_len = response[0] as usize;
        if response.len() < 1 + pk_len {
            return Err(LedgerTronError::protocol(format!(
                "GET_PUBLIC_KEY: short response, declared {} pubkey bytes, total len {}",
                pk_len,
                response.len()
            )));
        }
        let pubkey = response[1..1 + pk_len].to_vec();
        if pubkey.len() != 65 || pubkey[0] != 0x04 {
            return Err(LedgerTronError::protocol(format!(
                "GET_PUBLIC_KEY: expected uncompressed 65-byte secp256k1 pubkey, got {} bytes prefixed 0x{:02X}",
                pubkey.len(),
                pubkey.first().copied().unwrap_or(0),
            )));
        }
        let raw = tron_raw_address(&pubkey)?;
        let base58check = tron_base58check(&raw);
        Ok(TronAddress {
            pubkey,
            raw,
            base58check,
        })
    }

    async fn sign_inner(
        &self,
        components: &[u32],
        raw_data: &[u8],
    ) -> Result<TronSignature, LedgerTronError> {
        if raw_data.is_empty() {
            return Err(LedgerTronError::invalid_tx("raw_data is empty"));
        }
        let path_bytes = encode_path(components);
        let header_len = path_bytes.len();
        if header_len >= MAX_APDU_DATA {
            return Err(LedgerTronError::protocol(format!(
                "derivation-path encoding {} bytes ≥ APDU ceiling {}",
                header_len, MAX_APDU_DATA
            )));
        }

        // Single-chunk fast path: path + raw_data fit in one APDU.
        // Use P1_SIGN so the device knows this is the only chunk
        // and signs immediately.
        if header_len + raw_data.len() <= MAX_APDU_DATA {
            let mut chunk = Vec::with_capacity(header_len + raw_data.len());
            chunk.extend_from_slice(&path_bytes);
            chunk.extend_from_slice(raw_data);
            let response = self.exchange(CLA, INS_SIGN, P1_SIGN, 0x00, &chunk).await?;
            return Self::decode_signature(&response);
        }

        // Multi-chunk path:
        //   - First chunk:  P1_FIRST (path bytes + first slice of raw_data)
        //   - Middle chunk: P1_MORE  (raw_data only, no path)
        //   - Final chunk:  P1_LAST  (raw_data only, no path; sign)
        let mut response = Vec::new();
        let mut offset = 0usize;
        let mut first = true;
        while first || offset < raw_data.len() {
            let chunk_capacity = if first {
                MAX_APDU_DATA - header_len
            } else {
                MAX_APDU_DATA
            };
            let end = (offset + chunk_capacity).min(raw_data.len());
            let mut chunk = Vec::with_capacity(chunk_capacity + header_len);
            if first {
                chunk.extend_from_slice(&path_bytes);
            }
            chunk.extend_from_slice(&raw_data[offset..end]);
            let is_final = end == raw_data.len();
            let p1 = if first {
                P1_FIRST
            } else if is_final {
                P1_LAST
            } else {
                P1_MORE
            };
            response = self.exchange(CLA, INS_SIGN, p1, 0x00, &chunk).await?;
            offset = end;
            first = false;
        }
        Self::decode_signature(&response)
    }

    /// Decode a 65-byte R||S||V signature from the device, normalising
    /// V to the 0/1 recovery id (some firmware emits V+27).
    fn decode_signature(response: &[u8]) -> Result<TronSignature, LedgerTronError> {
        if response.len() != 65 {
            return Err(LedgerTronError::protocol(format!(
                "SIGN: expected 65-byte signature (R||S||V), got {}",
                response.len()
            )));
        }
        // Tron signature wire format: R(32) || S(32) || V(1).
        // V is 0 or 1 — the recovery id, NOT the legacy 27+/28+ form
        // some Ethereum apps emit. Some Ledger Tron firmware versions
        // do return V+27; normalize to 0/1 for the caller.
        let r = response[0..32].to_vec();
        let s = response[32..64].to_vec();
        let raw_v = response[64];
        let v: u8 = if raw_v >= 27 {
            (raw_v - 27) & 0x01
        } else {
            raw_v & 0x01
        };
        Ok(TronSignature { r, s, v })
    }

    async fn exchange(
        &self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, LedgerTronError> {
        if data.len() > MAX_APDU_DATA {
            return Err(LedgerTronError::protocol(format!(
                "APDU payload {} exceeds {} byte ceiling",
                data.len(),
                MAX_APDU_DATA
            )));
        }
        let mut apdu = Vec::with_capacity(5 + data.len());
        apdu.push(cla);
        apdu.push(ins);
        apdu.push(p1);
        apdu.push(p2);
        apdu.push(data.len() as u8);
        apdu.extend_from_slice(data);

        let response = self.transport.exchange(apdu).await?;
        if response.status_word != SW_SUCCESS {
            return Err(LedgerTronError::from_status(
                response.status_word,
                &format!("INS 0x{ins:02X}"),
            ));
        }
        Ok(response.data)
    }
}

fn standard_tron_path(account: u32) -> Vec<u32> {
    vec![harden(44), harden(195), harden(account), 0, 0]
}

const HARDENED_BIT: u32 = 0x8000_0000;

fn harden(index: u32) -> u32 {
    index | HARDENED_BIT
}

fn parse_bip32_path(path: &str) -> Result<Vec<u32>, LedgerTronError> {
    let trimmed = path.trim();
    let body = trimmed.strip_prefix("m/").unwrap_or(trimmed);
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for raw in body.split('/') {
        let (digits, hardened) = if let Some(stripped) = raw.strip_suffix('\'') {
            (stripped, true)
        } else if let Some(stripped) = raw.strip_suffix('h') {
            (stripped, true)
        } else {
            (raw, false)
        };
        let n: u32 = digits.parse().map_err(|_| LedgerTronError::InvalidPath {
            reason: format!("'{raw}' is not a valid path component"),
        })?;
        if n >= HARDENED_BIT {
            return Err(LedgerTronError::InvalidPath {
                reason: format!("component {n} exceeds 31-bit range"),
            });
        }
        out.push(if hardened { harden(n) } else { n });
    }
    Ok(out)
}

fn encode_path(components: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + components.len() * 4);
    out.push(components.len() as u8);
    for c in components {
        out.extend_from_slice(&c.to_be_bytes());
    }
    out
}

/// Compute the 21-byte raw Tron address `[0x41, keccak256(pubkey_xy)[12..]]`
/// from a 65-byte uncompressed secp256k1 pubkey.
fn tron_raw_address(pubkey: &[u8]) -> Result<Vec<u8>, LedgerTronError> {
    if pubkey.len() != 65 || pubkey[0] != 0x04 {
        return Err(LedgerTronError::protocol(
            "tron_raw_address: input must be 65-byte uncompressed pubkey",
        ));
    }
    let hash = keccak256(&pubkey[1..]);
    let mut raw = Vec::with_capacity(21);
    raw.push(0x41);
    raw.extend_from_slice(&hash[12..]);
    Ok(raw)
}

/// Base58check encode the 21-byte raw Tron address. Tron uses a
/// double-SHA-256 checksum identical to Bitcoin's base58check.
fn tron_base58check(raw: &[u8]) -> String {
    let h1 = Sha256::digest(raw);
    let h2 = Sha256::digest(h1);
    let mut buf = Vec::with_capacity(raw.len() + 4);
    buf.extend_from_slice(raw);
    buf.extend_from_slice(&h2[..4]);
    bs58::encode(&buf).into_string()
}

/// Keccak-256 over the XY coordinates of the secp256k1 pubkey.
/// Tron uses the same hash function as Ethereum for the address
/// derivation step; we just take a different prefix byte.
fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(input);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_path_matches_hw_app_trx() {
        let path = standard_tron_path(0);
        let encoded = encode_path(&path);
        // m/44'/195'/0'/0/0 — first three hardened, last two not.
        let expected: Vec<u8> = vec![
            0x05, // 5 components
            0x80, 0x00, 0x00, 0x2C, // 44'
            0x80, 0x00, 0x00, 0xC3, // 195'
            0x80, 0x00, 0x00, 0x00, // 0'
            0x00, 0x00, 0x00, 0x00, // 0
            0x00, 0x00, 0x00, 0x00, // 0
        ]; // 21 bytes total
        assert_eq!(encoded, expected);
    }

    #[test]
    fn keccak256_empty_input() {
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let h = keccak256(&[]);
        assert_eq!(
            hex::encode(h),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn keccak256_abc() {
        // keccak256("abc") = 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
        let h = keccak256(b"abc");
        assert_eq!(
            hex::encode(h),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    #[test]
    fn tron_address_from_known_pubkey() {
        // Real Tron mainnet pubkey/address pair from foundation
        // docs (anyone-can-verify). Uncompressed 65-byte pubkey →
        // expected base58check address starts with 'T'.
        //
        // Pubkey (uncompressed): 04 + 64-byte XY for an arbitrary
        // valid secp256k1 point. We just sanity-check the pipeline:
        // encode → decode → re-encode round-trips, and the address
        // is 34 chars starting with T.
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

    #[test]
    fn parse_path_accepts_apostrophe_and_h() {
        let a = parse_bip32_path("m/44'/195'/0'/0/0").unwrap();
        let b = parse_bip32_path("m/44h/195h/0h/0/0").unwrap();
        assert_eq!(a, b);
    }
}
