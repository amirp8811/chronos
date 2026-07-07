# CHRONOS cryptographic protocol specification (prototype v1)

Status: internal validation draft. This document describes the implemented prototype formats. It is not an externally reviewed production cryptographic specification.

## Security posture

Implemented primitives use standard building blocks where possible:

- ML-KEM-768 via RustCrypto `ml-kem` for post-quantum KEM material.
- X25519 via `x25519-dalek` for classical ECDH.
- HKDF-SHA256 for key derivation.
- ChaCha20-Poly1305 for AEAD secure cells and route layers.
- Ed25519 via `ed25519-dalek` for directory record/vote prototypes.

Custom protocol compositions in CHS7, CRP7, and RTE7 require independent review before production use.

## SecureShardCell: CHR7

Fixed app-cell size: 1,200 bytes.

Layout:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | magic `CHR7` |
| 4 | 1 | version = 1 |
| 5 | 1 | flags |
| 6 | 2 | plaintext payload length, big endian |
| 8 | 16 | route/session tag |
| 24 | 12 | AEAD nonce / sequence IV |
| 36 | 944 | padded ciphertext |
| 980 | 16 | ChaCha20-Poly1305 tag |
| 996 | 204 | reserved zero bytes |

AEAD:

- Key: 32-byte link key derived by HKDF-SHA256.
- Nonce: `seq_iv` field.
- AAD: bytes `0..36` plus the trailing reserved bytes, so reserved-space mutation fails AEAD authentication.
- Plaintext: 944-byte padded payload region.

Failure behavior:

- invalid magic/version/length/reserved bytes reject before decrypt,
- AEAD failure returns authentication error,
- payload length above 944 rejects.

## CHS7 handshake

Packet header:

| Field | Description |
|---|---|
| magic | `CHS7` |
| version | 1 |
| packet type | ServerHello, ClientKeyShare, ServerKeyConfirm, Error, PowChallenge, PowSolution |
| suite | `ML-KEM-768 + X25519 + ChaCha20-Poly1305` suite id |
| payload length | u16 big endian |

Handshake flow without PoW:

1. Server sends `ServerHello`: per-session ephemeral X25519 public key + per-session ephemeral ML-KEM-768 encapsulation key in the live `chronosd` handshake path. Static node keys identify/configure the relay but are not used as the live session KEM/ECDH secrets.
2. Client sends `ClientKeyShare`: X25519 public key + ML-KEM ciphertext.
3. Server decapsulates/derives the hybrid route secret.
4. Server sends `ServerKeyConfirm` = HKDF(route secret, transcript hash).
5. Client verifies confirmation.

Handshake flow with PoW:

1. Client sends empty `ServerHello` request.
2. Server sends a source-bound `PowChallenge` with a MAC-like token derived from source identity, time window, relay id, and a server secret.
3. Client sends `PowSolution`.
4. Server verifies PoW and then sends real `ServerHello`.
5. Normal key exchange proceeds.

Transcript hash:

```text
SHA256("chronos-v7-handshake-transcript" || encoded_server_hello || encoded_client_key_share)
```

Downgrade protection:

- version and suite are encoded into both transcript packets,
- unsupported suite values are rejected before key acceptance.

## Hybrid route secret

Input key material:

```text
ML-KEM shared secret || X25519 shared secret
```

KDF:

```text
HKDF-SHA256(salt = route_context, info = "chronos-v7/hybrid-mlkem768-x25519-route-hop")
```

Output: 32-byte `RouteHopSecret`.

## RTE7 route layer

`LayeredRoutePacket` serializes with magic `RTP7`, version, hop index, body length, packet id, and body.

Each encrypted hop body contains:

| Field | Description |
|---|---|
| next_stream_id | u64 big endian |
| flags | typed route command bits |
| reserved | zero bytes |
| inner length | u16 |
| inner bytes | next layer or payload |

Per-hop encryption:

- Key: HKDF-SHA256(packet id, hop index, hop secret).
- Nonce: packet id + hop index.
- AEAD: ChaCha20-Poly1305.
- AAD: route layer magic/version/hop/body length/packet id.

Route commands:

- Forward
- DeliverLocal
- Drop
- Reply

Constant-size relay invariant:

- CRP7 route packets pad the encoded RTE7 route payload to the fixed relay payload size before forwarding.
- `RelayPacket::route_packet` decodes only the declared RTE7 prefix and ignores authenticated relay padding.

Packet-id blinding:

The next hop packet id is derived with HKDF-SHA256 from current packet id, hop index, and hop secret. This gives concrete packet-id unlinkability at the envelope layer, but is not a formal Sphinx proof.

Replay:

`RouteReplayCache` rejects duplicate `(packet_id, hop_index)` entries and supports TTL/capacity eviction.

## CRP7 relay packet

Header size: 28 bytes.

Types:

- Hello
- Shard
- Ack
- Error
- Route
- Data

Errors are encoded with `RelayErrorCode` bytes, including NoRoute, NoSession, QueueFull, Drop, and Internal.

## Key storage

`NodeKeyMaterial` stores:

- X25519 private key bytes,
- ML-KEM-768 decapsulation seed.

Unix key files are written with mode `0600`.

## Explicit non-goals in current prototype

- This is not a formal Sphinx proof.
- This is not a production PIR construction.
- This is not a production BFT consensus protocol.
- This has not been externally audited.
