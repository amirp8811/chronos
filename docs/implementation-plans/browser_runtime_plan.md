# Browser WebSocket/WebTransport runtime plan

## Goal

Turn the web demo into a real browser client capable of calling WASM exports and communicating with a relay gateway.

## Current state

Implemented today:

- `chronos-wasm` wasm-bindgen exports for version, TDM planning, and secure-cell self-test.
- Web UI attempts to load `./pkg/chronos_wasm.js` and falls back gracefully.

Not implemented:

- WebSocket CRP7 transport.
- WebTransport CRP7 transport.
- Browser handshake flow.
- Binary packet UI.
- Browser end-to-end tests.

## Stage 1 — WebSocket transport module

Add:

```text
apps/chronos-web/chronos_ws_client.js
```

API:

```js
connect(url)
disconnect()
sendPacket(Uint8Array)
onPacket(callback)
onStatus(callback)
```

Validation gate:

- Unit-testable state transitions where possible.
- UI can load module without server.

## Stage 2 — WebSocket gateway/server

Options:

1. Add WebSocket listener directly to `chronosd`.
2. Add separate gateway translating WebSocket binary frames to UDP CRP7.

Recommendation:

Start with separate gateway to avoid mixing browser protocol complexity into relay core.

Validation gate:

- Browser -> WS gateway -> UDP relay -> ACK path.

## Stage 3 — UI integration

Add UI controls:

- relay URL input,
- connect/disconnect,
- send self-test packet,
- display ACK/error/data,
- display WASM status.

Validation gate:

- UI works without WASM bundle in fallback mode.
- UI uses WASM exports when bundle exists.

## Stage 4 — CHS7 handshake in browser

Add WASM/JS helpers:

- parse server hello,
- generate client key share,
- verify server confirm,
- build route packet.

Validation gate:

- Browser client can complete CHS7 handshake through gateway.

## Stage 5 — WebTransport adapter

Add feature detection:

```js
if ('WebTransport' in window) { ... }
```

Requirements:

- HTTPS/HTTP3 server,
- certificate setup,
- QUIC support.

Validation gate:

- Playwright/Chrome test in environment with WebTransport server.

## Stage 6 — Browser automation

Use Playwright:

- start relay/gateway,
- open page,
- connect,
- run self-test,
- assert ACK.

Validation gate:

- CI job or documented local command.

## Definition of done

- WebSocket client works end-to-end.
- UI can send and receive real binary packets.
- CHS7 browser flow works.
- WebTransport adapter exists with feature detection.
- Browser automation test exists.
