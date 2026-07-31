# CHRONOS Security Boundaries and Validation

## Scope statement

CHRONOS is an experimental codebase. It has not undergone an independent
security assessment and is **not safe for production anonymity, safety-critical
use, or protection of sensitive identities**. Tests demonstrate selected code
properties; they do not prove anonymity or resistance to a network adversary.

## Implemented security invariants

The following invariants are covered by unit tests where practical:

- Secure cells authenticate metadata and ciphertext before plaintext is exposed.
- Receive replay state advances only after cell authentication succeeds.
- Route replay state advances only after the route layer authenticates and
  parses successfully.
- Route packet identifiers are blinded between hops; the safe builder obtains a
  fresh identifier from an operating-system random source.
- Client handshakes require a caller-supplied expected stable relay identity,
  rather than accepting any self-signed hello.
- The UDP relay serves its persisted node identity for hello requests; it does
  not create a new relay identity per connection.
- Directory records require non-zero public material, a valid self-signature,
  and an unexpired bounded lifetime on the default API path.
- Proof-of-work challenge tokens bind relay ID, client address, difficulty, and
  time window to a configured server secret. Spent challenge-token/nonce pairs
  are rejected while retained.

## Known limits

- No external cryptographic, protocol, or implementation audit has been
  completed.
- Bounded replay caches can forget old entries under expiry or capacity
  pressure. This is documented behaviour, not a complete replay defense.
- Relay identity distribution, key rotation, revocation, and directory
  authorization are not designed as a deployable system.
- The relay's optional send delay does not generate cover traffic and does not
  establish constant-rate traffic shaping.
- Local metrics and simulations are engineering experiments, not privacy
  proofs.
- Client apps, directory consensus, and high-performance dataplane paths are
  not supported deployments.

## Validation commands

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo check -p chronos-core --no-default-features
python3 scripts/static_audit.py
```

The repository also contains fuzz targets where a compatible fuzzing toolchain
is available. They are useful for finding parser faults, but they are not a
substitute for review.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to
[amirp8811@gmail.com](mailto:amirp8811@gmail.com). Include affected revision,
reproduction steps, impact assessment, and any relevant test input. Please do
not publish exploit details before a maintainer has had a reasonable opportunity
to investigate.
