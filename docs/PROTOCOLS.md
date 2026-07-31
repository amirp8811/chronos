# CHRONOS implemented protocol notes

This document describes implemented prototype wire formats. It is not the full target specification.

## Secure app cell

`SecureShardCell` is a fixed 1,200 byte app-cell envelope with magic `CHR7`, version, flags, payload length, route tag, sequence IV, 944 bytes of padded ciphertext, and a 16 byte ChaCha20-Poly1305 tag.

## Shard stream

`SecureShardBlockCodec` splits one plaintext block into 10 data shards and 6 parity shards, encrypting each shard as a `SecureShardCell`.

## CHS7 handshake

CHS7 packets include `ServerHello`, `ClientKeyShare`, `ServerKeyConfirm`, and `Error`. The handshake combines ML-KEM-768 and X25519 into a transcript-bound route secret and uses HKDF key confirmation.

## CRP7 relay packet

CRP7 relay packets include `Hello`, `Shard`, `Ack`, `Error`, `Route`, and `Data`. Error packets can carry a binary `RelayErrorCode`.

## RTE7 route layer

RTE7 route packets wrap payloads in per-hop ChaCha20-Poly1305 layers, support packet-id blinding, typed route commands, replay caches, and single-use reply blocks.
