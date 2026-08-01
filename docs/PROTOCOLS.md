# CHRONOS Implemented Protocol Notes

This document describes code that exists in the repository today. It is not a
network specification and it does not make a production-security claim.

## CHR7 secure application cell

`SecureShardCell` is a fixed 1,200-byte application envelope:

| Field | Bytes | Notes |
| --- | ---: | --- |
| Magic and version | 5 | Identifies the current cell format. |
| Flags and payload length | 3 | Authenticated metadata. |
| Route tag | 16 | Selects the caller's key/route context. |
| Sequence IV | 12 | ChaCha20-Poly1305 nonce encoding. |
| Ciphertext | 944 | Padded plaintext area. |
| Authentication tag | 16 | ChaCha20-Poly1305 tag. |
| Reserved area | 204 | Required to be zero and covered by associated data. |

New senders should use `SecureCellSender`. It allocates a monotonically
increasing sequence value per `(key, route tag)` domain. The lower-level
constructor takes a caller-provided sequence for deterministic vectors and
externally managed sequence allocators; reusing it with the same key and route
tag reuses an AEAD nonce and is unsafe.

## CHS7 handshake

A CHS7 server hello contains X25519 and ML-KEM-768 public material, a stable
Ed25519 identity public key, and a signature over those fields. The client API
requires an expected identity and rejects a correctly self-signed hello from a
different identity. The key share and server confirmation are bound to the
encoded transcript.

The implementation provides a protocol primitive only. It does not define how
a client discovers, rotates, revokes, or trusts relay identities.

## RTE7 route layer

RTE7 wraps a payload in one authenticated layer for each chosen hop. A layer
contains a route command, the next stream identifier, the inner length, and an
AEAD tag. Forwarding derives a blinded packet identifier for the next hop.

A relay authenticates and parses a layer before inserting its identifier into
replay state. That ordering prevents an unauthenticated forgery from reserving
a legitimate identifier. Replay retention is bounded in both size and time; an
entry may be forgotten after expiry or capacity eviction.

`RoutePacketBuilder` is the safe constructor for ordinary use. It obtains a
fresh packet identifier from the operating system random source. The explicit
identifier builder remains for test vectors and caller-owned allocators only.
It is the caller's responsibility not to reuse identifiers with the same hop
secret.

## CRP7 local relay envelope

CRP7 is the packet envelope used by local UDP relay tests. Its packet types are
`Hello`, `Shard`, `Ack`, `Error`, `Route`, and `Data`. It is an experimental
relay format and has not been validated as a public transport protocol.

## Proof-of-work admission

The UDP prototype can encode a challenge carrying a relay ID, time window,
difficulty, and token. The token is derived from a configured server secret and
is bound to the client address, relay ID, difficulty, and window. A replay cache
rejects an already spent challenge-token/nonce pair. The daemon requires a
configured secret to turn this feature on; there is no default admission secret.

## Directory record API

The local directory process accepts `UPSERT_SIGNED` records only by default.
A record includes the relay address, real X25519 public key, ML-KEM public-key
hash, expiry, Ed25519 public key, and signature. Records with zero public
material, bad signatures, excessive lifetime, or expiration are rejected. The
on-disk `CHDIR002` format persists those signed fields and verifies every record
again during load; the earlier stripped-record format is rejected.

The plaintext `UPSERT` and remote `PRUNE` commands are disabled by default.
They can be enabled only with explicit local-development environment switches.
This line protocol is not a public directory, publication, or administration
interface.

## Simulation-only onion header

The optional `simulation` feature retains a small header-mutation demonstration
for test and teaching use. It is excluded from the default public API and does
not provide authenticated routing or a production cryptographic construction.
