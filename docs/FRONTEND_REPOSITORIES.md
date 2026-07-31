# Frontend Repositories

The CHRONOS application runtimes are maintained as separate repositories from the core to reduce attack surface and build complexity.

## chronos-web
- Consumes the `@chronos/engine-wasm` npm package.
- Built from the `chronos-wasm` target in this repository.

## chronos-mobile (Android/iOS)
- Consumes native UniFFI / C-ABI headers.
- Built from the `chronos-lite` or `chronos-core` targets.
