# Contributing to CHRONOS

We welcome contributions from systems engineers, cryptographers, and privacy advocates.

---

## 1. Getting Started
1. Familiarize yourself with the **Anonymity Trilemma** and TDM mixnet models.
2. Ensure you have the latest Rust toolchain installed.
3. Check the **Implementation Status** in `ARCHITECTURE.md` for open tasks.

### Good First Issues
- Standardizing logging in `chronos-lite`.
- Adding unit tests for Galois field edge cases.
- Improving the `mdBook` documentation site.

---

## 2. Governance Model
CHRONOS currently operates under a **Benevolent Dictator for Life (BDFL)** model, led by Amir P (@amirp8811). Major architectural decisions are managed via GitHub RFCs.

---

## 3. Code of Conduct
We are committed to a harassment-free environment. All participants are expected to act professionally and respectfully. 

---

## 4. Developer Automation
The project uses a `Justfile` for common tasks:
- `just docs`: Build the documentation book.
- `just validate`: Run the security audit suite.
- `just verify`: Run formal verification (requires Kani).
