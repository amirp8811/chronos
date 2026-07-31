# Contributing to CHRONOS

Contributions are welcome when they make the prototype more correct, explicit,
and reviewable. Read the [implementation status](docs/ARCHITECTURE.md) and
[security boundaries](SECURITY.md) before proposing a feature.

## Before opening a pull request

1. Keep the change focused and describe any public API or wire-format impact.
2. Do not remove tests to hide a failure. Add a regression test for a security
   or correctness fix where practical.
3. Label simulated, planned, and unsupported behaviour accurately in code and
   documentation.
4. Run the required validation commands in [RULES.md](RULES.md).

Useful contribution areas include parser tests, boundary tests for protocol
primitives, no-`std` compatibility, audit tooling, documentation clarity, and
reproducible local experiments.

## Governance

CHRONOS uses centralized architectural direction led by Amir P (@amirp8811).
Major changes are discussed through repository issues and pull requests.

## Conduct

All participants are expected to act professionally, respectfully, and in good
faith. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
