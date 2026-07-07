# ledger-tron-rs

A Rust core + [UniFFI](https://github.com/mozilla/uniffi-rs) bindings for talking to the
**Ledger Tron app** from iOS and Android. The Rust crate implements the
Ledger Tron app's APDU protocol directly (address derivation and transaction signing),
while the host platform owns its own BLE transport.

Single source of truth, two artifacts:

```
ledger-tron-rs/
   ├── ledger-tron-core   ←  Rust crate (LedgerTronClient)
   ├── ios                ←  build-xcframework.sh → LedgerTronCore.xcframework
   └── android            ←  android/build-aar.sh → ledger-tron-core.aar
```

The Trezor counterpart across all four chains is `trezor-core-rs` (one unified crate).

## Design pillars

1. **Audit surface = Ledger device protocol only.** No Tron RPC / SDK dependency; the
   crate speaks the Ledger Tron app protocol and nothing else.
2. **Native owns transport.** BLE framing, MTU chunking, and keep-alive live on the
   Swift side; Rust gets complete APDUs in, complete responses out.
3. **Async end-to-end.** The UniFFI callback transport is async; the client is `async`
   throughout (Swift sees `async throws`). Addresses are base58check-encoded.

## Public API

```rust
let client = LedgerTronClient::new(my_transport);
let cfg:  Vec<u8> = client.get_app_configuration().await?;
let addr: String  = client.get_address_at_path("m/44'/195'/0'/0/0".into(), false).await?;
let sig:  Vec<u8> = client.sign_transaction_at_path(path, raw_tx).await?;
```

`*_for_account` convenience variants take an account index instead of a full path.

## Building

```sh
make                    # fmt-check + clippy + test (CI default)
make ios                # produces ios/LedgerTronCore.xcframework (run setup-ios-targets once)
./android/build-aar.sh  # produces the ledger-tron-core.aar for Android
make clean
```

## License

Apache-2.0.

## Acknowledgements

- [Mozilla UniFFI](https://github.com/mozilla/uniffi-rs) for the cross-language binding generator.
- Ledger's Tron app APDU specification.
