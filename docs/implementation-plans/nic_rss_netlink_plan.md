# Privileged NIC RSS netlink/ethtool execution plan

## Goal

Move from Toeplitz RSS command construction to safe, explicit execution of RSS key updates on supported Linux hosts.

## Current state

Implemented today:

- Toeplitz salt simulation.
- `build_ethtool_toeplitz_args` argument construction and validation.

Not implemented:

- actual command execution,
- netlink/libbpf API,
- privilege checks,
- NIC capability checks,
- rollback/verification.

## Stage 1 — Execution abstraction

Define trait:

```rust
pub trait NicRssController {
    fn supports_rss_key_update(&self, iface: &str) -> Result<bool, NicError>;
    fn set_toeplitz_key(&self, iface: &str, key: &[u8; 40]) -> Result<(), NicError>;
    fn get_toeplitz_key(&self, iface: &str) -> Result<Option<[u8; 40]>, NicError>;
}
```

Implement first:

- `DryRunNicRssController`
- `CommandEttoolController`

Validation gate:

- Dry-run tests.
- Command construction tests.

## Stage 2 — Privilege/capability checks

Check:

- running as root or CAP_NET_ADMIN,
- `ethtool` exists if command backend used,
- interface exists.

Validation gate:

- unprivileged tests return structured `PermissionDenied`.

## Stage 3 — ethtool execution backend

Implement command backend:

```text
ethtool -X eth0 hkey <hex-key>
```

Guardrails:

- no shell invocation, use `Command` args,
- validate interface string,
- validate 40-byte key,
- timeout command,
- capture stderr.

Validation gate:

- mocked command runner tests.
- ignored integration test for real host.

## Stage 4 — netlink backend

Preferred long-term backend.

Evaluate crates:

- `netlink-packet-ethtool`
- `netlink-sys`
- `rtnetlink`

Validation gate:

- feature-gated netlink backend compiles.
- read-only capability query works without mutation where possible.

## Stage 5 — Runtime integration

Integrate into `ToeplitzSaltShuffler`:

- dry-run by default,
- explicit config flag for real mutation,
- metrics for update attempts/success/failure.

Validation gate:

- default does not mutate NIC.
- real mode requires explicit config.

## Stage 6 — Verification and rollback

If possible:

- read old key,
- set new key,
- verify applied,
- rollback on failure.

Validation gate:

- mocked rollback tests.

## Risks

- Requires privileges.
- Can disrupt networking.
- NIC/driver support varies.

## Definition of done

- Dry-run controller and command backend implemented.
- Privilege checks implemented.
- Real mutation guarded by explicit config.
- Verification/rollback or documented limitations.
- Manual hardware test instructions.
