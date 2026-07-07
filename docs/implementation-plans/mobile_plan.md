# iOS/Android client implementation plan

## Goal

Build native mobile clients that can store keys, connect to relay/gateway transports, perform CHS7 handshakes, and send/receive CRP7 packets.

## Current state

Implemented today:

- iOS/Android scaffold README files.
- Core protocol logic in Rust.

Not implemented:

- Native projects.
- Key storage.
- Network adapters.
- UI.
- Platform tests.

## Stage 1 — Shared FFI strategy

Options:

1. Rust core compiled to mobile static libraries via UniFFI.
2. Kotlin/Swift reimplement packet glue and call server APIs.
3. Use WASM in mobile WebView.

Recommendation:

Use UniFFI for Rust core bindings.

Validation gate:

- `chronos-mobile-core` crate builds bindings for Swift/Kotlin.

## Stage 2 — iOS skeleton

Add:

```text
apps/chronos-mobile/ios/ChronosClient/
```

Implement:

- Swift package or Xcode project,
- Keychain key storage wrapper,
- relay URL config,
- packet send/receive interface.

Validation gate:

- builds in Xcode or documented CLI.

## Stage 3 — Android skeleton

Add:

```text
apps/chronos-mobile/android/
```

Implement:

- Gradle project,
- Android Keystore wrapper,
- foreground service placeholder,
- packet transport interface.

Validation gate:

- Gradle build documented.

## Stage 4 — Transport

Start with WebSocket:

- easier than UDP from mobile networks,
- works with gateway,
- shares browser path.

Validation gate:

- mobile client can connect to WS gateway.

## Stage 5 — CHS7 and route send

Use FFI to:

- parse server hello,
- create key share,
- verify confirm,
- build route packet.

Validation gate:

- local emulator/simulator handshake test.

## Stage 6 — Lifecycle and power

Implement:

- foreground-only sessions first,
- background disabled until reviewed,
- later WorkManager/iOS background task policies.

Validation gate:

- no background network claims until platform-tested.

## Definition of done

- iOS and Android skeletons build.
- Key storage wrappers exist.
- WebSocket transport exists.
- CHS7 handshake works against local gateway.
- Basic UI can connect/send/test packet.
