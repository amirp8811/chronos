# CHRONOS web app integration plan

The current `index.html` is a static demo dashboard. The Rust crate now exposes
minimal wasm-bindgen functions in `chronos-wasm::bindings`:

- `chronos_wasm_version()`
- `chronos_plan_tdm_slots(slots, data_cells, cover_when_idle)`
- `chronos_secure_cell_self_test(message)`

Next browser work:

1. Build `chronos-wasm` for `wasm32-unknown-unknown` with `wasm-bindgen`.
2. Load the generated JS/WASM bundle from this app.
3. Replace simulated console actions with calls into the WASM exports.
4. Add WebTransport/WebSocket transport adapters after the local protocol stabilizes.
