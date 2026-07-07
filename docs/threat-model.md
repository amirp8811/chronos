# CHRONOS prototype threat model

Status: internal draft for validation. This document distinguishes implemented protections from target-spec goals.

## Assets

- Payload confidentiality.
- Packet integrity.
- Route command confidentiality per hop.
- Relay replay resistance.
- Session/route secret confidentiality.
- Directory record authenticity in the prototype directory.

## Adversaries

### A1: Passive network observer on one link

Can observe packet timing, packet size, source/destination addresses for one link. Cannot decrypt AEAD-protected payloads.

Implemented protections:

- Secure cells encrypt payloads.
- CRP7/RTE7 parsers validate packet structure.

Not fully protected:

- timing patterns,
- traffic volume,
- connection metadata.

### A2: Malicious relay

Controls one relay and sees packets arriving to it.

Implemented protections:

- per-hop route layer reveals only that hop's command,
- downstream packet id is blinded,
- route replay cache rejects duplicates.

Not fully protected:

- malicious relay can drop/delay packets,
- full route unlinkability has not been formally proven.

### A3: Global passive adversary

Can observe all links.

Implemented protections:

- encryption and route-layer confidentiality.

Not implemented/validated:

- strong timing unlinkability,
- intersection-attack resistance,
- global passive adversary anonymity proof.

### A4: Active network adversary

Can inject, modify, replay, drop, and reorder packets.

Implemented protections:

- AEAD rejects tampering,
- replay caches reject duplicate route/relay sequences,
- typed error paths exist.

Remaining gaps:

- large-scale DoS resilience,
- adaptive cover/pacing policy under attack.

### A5: Malicious directory participant

Can submit bad records or bad votes.

Implemented protections:

- Ed25519 signed records,
- quorum-backed commit prototype,
- tampered vote rejection.

Remaining gaps:

- full BFT view changes,
- validator networking,
- persistent consensus log.

## Claims currently supported

- Payload confidentiality for secure cells under standard AEAD assumptions.
- Integrity for secure cells, route layers, and relay packets.
- CHS7 key confirmation and downgrade rejection in tests.
- ML-KEM-768 + X25519 route secret agreement in tests.
- Local multi-hop route processing in tests.

## Claims not yet supported

- Production anonymity against a global passive adversary.
- Production DPF/PIR privacy.
- Production BFT directory consensus.
- Production mobile/browser transport security.
- Hardware data-plane hardening claims.

## Required validation before production claims

- Independent cryptographic review.
- Independent implementation audit.
- Continuous fuzzing.
- Real network trace collection.
- Adversarial traffic-analysis evaluation.
- Platform-specific browser/mobile testing.
