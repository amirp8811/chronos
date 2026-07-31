# CHRONOS browser demonstration

`index.html` is a static, local demonstration page. It is **not** a browser
client, relay connection, anonymity measurement, or privacy proof.

If a locally built `chronos-wasm` bundle is placed in `pkg/`, the page can run
one exposed secure-cell self-test. That result only demonstrates the local test
function; it does not establish transport or network security.

## Current status

| Item | Status |
| --- | --- |
| Static page and local probe button | Implemented demonstration |
| WebAssembly bundle build | Manual development step |
| Network transport | Not implemented |
| Relay discovery and identity distribution | Not implemented |
| Production browser client | Unsupported |
