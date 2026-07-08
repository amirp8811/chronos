# Details

Date : 2026-07-08 21:01:14

Directory c:\\Users\\AmirP\\chronos\\crates

Total : 63 files,  8610 codes, 310 comments, 1011 blanks, all 9931 lines

[Summary](results.md) / Details / [Diff Summary](diff.md) / [Diff Details](diff-details.md)

## Files
| filename | language | code | comment | blank | total |
| :--- | :--- | ---: | ---: | ---: | ---: |
| [crates/chronos-core/benches/constant\_time.rs](/crates/chronos-core/benches/constant_time.rs) | Rust | 10 | 1 | 3 | 14 |
| [crates/chronos-core/src/clock.rs](/crates/chronos-core/src/clock.rs) | Rust | 23 | 1 | 5 | 29 |
| [crates/chronos-core/src/framing.rs](/crates/chronos-core/src/framing.rs) | Rust | 64 | 4 | 13 | 81 |
| [crates/chronos-core/src/gf28.rs](/crates/chronos-core/src/gf28.rs) | Rust | 217 | 21 | 29 | 267 |
| [crates/chronos-core/src/handshake.rs](/crates/chronos-core/src/handshake.rs) | Rust | 76 | 9 | 20 | 105 |
| [crates/chronos-core/src/handshake\_protocol.rs](/crates/chronos-core/src/handshake_protocol.rs) | Rust | 587 | 7 | 47 | 641 |
| [crates/chronos-core/src/hybrid\_route.rs](/crates/chronos-core/src/hybrid_route.rs) | Rust | 168 | 6 | 24 | 198 |
| [crates/chronos-core/src/kani\_harness.rs](/crates/chronos-core/src/kani_harness.rs) | Rust | 10 | 2 | 3 | 15 |
| [crates/chronos-core/src/kat\_tests.rs](/crates/chronos-core/src/kat_tests.rs) | Rust | 10 | 2 | 2 | 14 |
| [crates/chronos-core/src/key\_store.rs](/crates/chronos-core/src/key_store.rs) | Rust | 184 | 5 | 18 | 207 |
| [crates/chronos-core/src/lib.rs](/crates/chronos-core/src/lib.rs) | Rust | 60 | 0 | 5 | 65 |
| [crates/chronos-core/src/mix\_policy.rs](/crates/chronos-core/src/mix_policy.rs) | Rust | 28 | 1 | 4 | 33 |
| [crates/chronos-core/src/pow.rs](/crates/chronos-core/src/pow.rs) | Rust | 131 | 10 | 24 | 165 |
| [crates/chronos-core/src/pow\_admission.rs](/crates/chronos-core/src/pow_admission.rs) | Rust | 196 | 1 | 16 | 213 |
| [crates/chronos-core/src/ratchet.rs](/crates/chronos-core/src/ratchet.rs) | Rust | 48 | 2 | 10 | 60 |
| [crates/chronos-core/src/relay\_handler.rs](/crates/chronos-core/src/relay_handler.rs) | Rust | 169 | 10 | 25 | 204 |
| [crates/chronos-core/src/relay\_packet.rs](/crates/chronos-core/src/relay_packet.rs) | Rust | 397 | 6 | 38 | 441 |
| [crates/chronos-core/src/route\_layer.rs](/crates/chronos-core/src/route_layer.rs) | Rust | 631 | 12 | 67 | 710 |
| [crates/chronos-core/src/secure\_cell.rs](/crates/chronos-core/src/secure_cell.rs) | Rust | 332 | 34 | 40 | 406 |
| [crates/chronos-core/src/session.rs](/crates/chronos-core/src/session.rs) | Rust | 131 | 1 | 16 | 148 |
| [crates/chronos-core/src/shard\_stream.rs](/crates/chronos-core/src/shard_stream.rs) | Rust | 286 | 7 | 36 | 329 |
| [crates/chronos-core/src/sphinx.rs](/crates/chronos-core/src/sphinx.rs) | Rust | 66 | 12 | 18 | 96 |
| [crates/chronos-core/src/tdm.rs](/crates/chronos-core/src/tdm.rs) | Rust | 64 | 4 | 9 | 77 |
| [crates/chronos-core/src/traffic\_analysis.rs](/crates/chronos-core/src/traffic_analysis.rs) | Rust | 176 | 5 | 16 | 197 |
| [crates/chronos-dir/src/api.rs](/crates/chronos-dir/src/api.rs) | Rust | 122 | 6 | 7 | 135 |
| [crates/chronos-dir/src/consensus.rs](/crates/chronos-dir/src/consensus.rs) | Rust | 111 | 7 | 17 | 135 |
| [crates/chronos-dir/src/consensus\_store.rs](/crates/chronos-dir/src/consensus_store.rs) | Rust | 175 | 6 | 20 | 201 |
| [crates/chronos-dir/src/main.rs](/crates/chronos-dir/src/main.rs) | Rust | 56 | 3 | 8 | 67 |
| [crates/chronos-dir/src/signed\_record.rs](/crates/chronos-dir/src/signed_record.rs) | Rust | 61 | 1 | 8 | 70 |
| [crates/chronos-dir/src/store.rs](/crates/chronos-dir/src/store.rs) | Rust | 145 | 1 | 10 | 156 |
| [crates/chronos-lite/src/config.rs](/crates/chronos-lite/src/config.rs) | Rust | 221 | 5 | 30 | 256 |
| [crates/chronos-lite/src/dpf\_store.rs](/crates/chronos-lite/src/dpf_store.rs) | Rust | 402 | 0 | 37 | 439 |
| [crates/chronos-lite/src/main.rs](/crates/chronos-lite/src/main.rs) | Rust | 360 | 4 | 19 | 383 |
| [crates/chronos-lite/src/secure\_udp.rs](/crates/chronos-lite/src/secure_udp.rs) | Rust | 261 | 9 | 34 | 304 |
| [crates/chronos-lite/src/webrtc\_turn.rs](/crates/chronos-lite/src/webrtc_turn.rs) | Rust | 42 | 0 | 5 | 47 |
| [crates/chronos-sys-dataplane/src/af\_xdp\_proto.rs](/crates/chronos-sys-dataplane/src/af_xdp_proto.rs) | Rust | 51 | 5 | 10 | 66 |
| [crates/chronos-sys-dataplane/src/io\_uring\_proto.rs](/crates/chronos-sys-dataplane/src/io_uring_proto.rs) | Rust | 47 | 4 | 10 | 61 |
| [crates/chronos-sys-dataplane/src/lib.rs](/crates/chronos-sys-dataplane/src/lib.rs) | Rust | 24 | 0 | 5 | 29 |
| [crates/chronos-sys-dataplane/src/ring\_model.rs](/crates/chronos-sys-dataplane/src/ring_model.rs) | Rust | 85 | 6 | 17 | 108 |
| [crates/chronos-sys-dataplane/src/timestamping.rs](/crates/chronos-sys-dataplane/src/timestamping.rs) | Rust | 16 | 3 | 2 | 21 |
| [crates/chronos-sys-dataplane/src/umem.rs](/crates/chronos-sys-dataplane/src/umem.rs) | Rust | 26 | 3 | 5 | 34 |
| [crates/chronos-wasm/src/bindings.rs](/crates/chronos-wasm/src/bindings.rs) | Rust | 22 | 2 | 4 | 28 |
| [crates/chronos-wasm/src/equihash.rs](/crates/chronos-wasm/src/equihash.rs) | Rust | 47 | 4 | 9 | 60 |
| [crates/chronos-wasm/src/hydra\_tcp.rs](/crates/chronos-wasm/src/hydra_tcp.rs) | Rust | 53 | 3 | 10 | 66 |
| [crates/chronos-wasm/src/imes.rs](/crates/chronos-wasm/src/imes.rs) | Rust | 50 | 3 | 11 | 64 |
| [crates/chronos-wasm/src/lib.rs](/crates/chronos-wasm/src/lib.rs) | Rust | 44 | 9 | 12 | 65 |
| [crates/chronos-wasm/src/mobile\_power.rs](/crates/chronos-wasm/src/mobile_power.rs) | Rust | 44 | 3 | 8 | 55 |
| [crates/chronos-wasm/src/stego\_ws.rs](/crates/chronos-wasm/src/stego_ws.rs) | Rust | 55 | 3 | 12 | 70 |
| [crates/chronos-wasm/src/transport.rs](/crates/chronos-wasm/src/transport.rs) | Rust | 44 | 5 | 10 | 59 |
| [crates/chronosd/src/af\_xdp\_proto.rs](/crates/chronosd/src/af_xdp_proto.rs) | Rust | 28 | 1 | 5 | 34 |
| [crates/chronosd/src/cache\_resctrl.rs](/crates/chronosd/src/cache_resctrl.rs) | Rust | 22 | 2 | 7 | 31 |
| [crates/chronosd/src/config.rs](/crates/chronosd/src/config.rs) | Rust | 223 | 1 | 11 | 235 |
| [crates/chronosd/src/dataplane\_probe.rs](/crates/chronosd/src/dataplane_probe.rs) | Rust | 47 | 1 | 5 | 53 |
| [crates/chronosd/src/io\_uring\_proto.rs](/crates/chronosd/src/io_uring_proto.rs) | Rust | 26 | 1 | 5 | 32 |
| [crates/chronosd/src/main.rs](/crates/chronosd/src/main.rs) | Rust | 145 | 7 | 16 | 168 |
| [crates/chronosd/src/metrics.rs](/crates/chronosd/src/metrics.rs) | Rust | 25 | 0 | 5 | 30 |
| [crates/chronosd/src/mixing\_engine.rs](/crates/chronosd/src/mixing_engine.rs) | Rust | 62 | 4 | 9 | 75 |
| [crates/chronosd/src/nic\_control.rs](/crates/chronosd/src/nic_control.rs) | Rust | 44 | 4 | 4 | 52 |
| [crates/chronosd/src/pow\_admission.rs](/crates/chronosd/src/pow_admission.rs) | Rust | 29 | 4 | 7 | 40 |
| [crates/chronosd/src/queue.rs](/crates/chronosd/src/queue.rs) | Rust | 66 | 1 | 7 | 74 |
| [crates/chronosd/src/socket\_tiering.rs](/crates/chronosd/src/socket_tiering.rs) | Rust | 96 | 6 | 10 | 112 |
| [crates/chronosd/src/toeplitz\_rss.rs](/crates/chronosd/src/toeplitz_rss.rs) | Rust | 64 | 10 | 9 | 83 |
| [crates/chronosd/src/udp\_relay.rs](/crates/chronosd/src/udp_relay.rs) | Rust | 1,105 | 10 | 103 | 1,218 |

[Summary](results.md) / Details / [Diff Summary](diff.md) / [Diff Details](diff-details.md)