#!/usr/bin/env python3
"""Small, dependency-free policy checks for the prototype workspace.

This script intentionally complements (rather than replaces) the Rust compiler,
clippy, dependency review, and cryptographic review. Keep allowlists narrow and
explain every exception in source control.
"""

from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
SCAN_DIRS = [ROOT / "crates", ROOT / "tools"]
UNSAFE_ALLOWED_CRATES = {"chronos-sys-dataplane"}
# These core modules are intentionally compiled in `--no-default-features` mode.
NO_STD_CORE_MODULES = {
    "clock.rs",  # `StdClock` itself is feature-gated inside this file.
    "fountain.rs",
    "framing.rs",
    "gf28.rs",
    "handshake.rs",
    "mix_policy.rs",
    "secure_cell.rs",
    "shard_stream.rs",
    "sphinx_sim.rs",
}

UNSAFE_CODE = re.compile(r"\bunsafe\b")
# This finds values assigned directly to variables/constants whose *names* imply
# credentials. It deliberately does not flag protocol-domain labels such as
# `b\"chronos-v7-pow-token\"`.
HARDCODED_CREDENTIAL = re.compile(
    r"\b(?:const|static|let)\s+\w*(?:secret|password|token|api_key|private_key)\w*"
    r"[^=;\n]*=\s*(?:b)?[\"']",
    re.IGNORECASE,
)


def crate_name_for(path: Path) -> str | None:
    rel = path.relative_to(ROOT)
    parts = rel.parts
    if len(parts) >= 2 and parts[0] == "crates":
        return parts[1]
    return None


def strip_comments(text: str) -> str:
    """Enough lexical filtering to avoid treating comments as unsafe code."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def check_file(path: Path) -> list[str]:
    text = path.read_text(errors="replace")
    code = strip_comments(text)
    rel = path.relative_to(ROOT)
    failures: list[str] = []
    crate = crate_name_for(path)

    if crate not in UNSAFE_ALLOWED_CRATES:
        for match in UNSAFE_CODE.finditer(code):
            line = code.count("\n", 0, match.start()) + 1
            line_text = code.splitlines()[line - 1]
            if "deny(unsafe_code)" not in line_text:
                failures.append(f"{rel}:{line}: forbidden unsafe code outside HAL")

    for match in HARDCODED_CREDENTIAL.finditer(code):
        line = code.count("\n", 0, match.start()) + 1
        failures.append(
            f"{rel}:{line}: credential-like literal assigned in source; use configured input or CSPRNG"
        )

    if path.parent.name == "src" and path.name in NO_STD_CORE_MODULES:
        for match in re.finditer(r"\bstd::", code):
            line = code.count("\n", 0, match.start()) + 1
            # A std import/adapter is permitted only when its immediately
            # preceding attribute explicitly gates it behind the std feature.
            lines = code.splitlines()
            previous = lines[line - 2].strip() if line >= 2 else ""
            if previous == '#[cfg(feature = "std")]':
                continue
            if path.name == "clock.rs":
                preceding = code[max(0, match.start() - 200):match.start()]
                if 'cfg(feature = "std")' in preceding:
                    continue
            failures.append(f"{rel}:{line}: std:: use in no_std core module")

    if path.name == "sphinx_sim.rs" and "Poly1305" in text:
        failures.append(
            f"{rel}: simulation must not claim a Poly1305 construction without using that primitive"
        )
    return failures


def check_crate_roots() -> list[str]:
    failures: list[str] = []
    for manifest in list((ROOT / "crates").glob("*/Cargo.toml")) + list(
        (ROOT / "tools").glob("*/Cargo.toml")
    ):
        crate_dir = manifest.parent
        if crate_dir.name in UNSAFE_ALLOWED_CRATES:
            continue
        roots = [crate_dir / "src" / "lib.rs", crate_dir / "src" / "main.rs"]
        for root in roots:
            if root.exists() and "#![deny(unsafe_code)]" not in root.read_text(errors="replace"):
                failures.append(
                    f"{root.relative_to(ROOT)}: crate root must declare #![deny(unsafe_code)]"
                )
    return failures


def check_fuzz_target_registration() -> list[str]:
    """Require every target source to be a real registered cargo-fuzz binary."""
    manifest_path = ROOT / "fuzz" / "Cargo.toml"
    target_dir = ROOT / "fuzz" / "fuzz_targets"
    if not manifest_path.exists() and not target_dir.exists():
        return []
    if not manifest_path.exists() or not target_dir.exists():
        return ["fuzz: manifest and fuzz_targets directory must exist together"]

    try:
        manifest = tomllib.loads(manifest_path.read_text())
    except tomllib.TOMLDecodeError as error:
        return [f"fuzz/Cargo.toml: invalid TOML: {error}"]

    bins = manifest.get("bin", [])
    registered: set[Path] = set()
    failures: list[str] = []
    for binary in bins:
        path_value = binary.get("path")
        name = binary.get("name")
        if not isinstance(name, str) or not isinstance(path_value, str):
            failures.append("fuzz/Cargo.toml: every [[bin]] needs name and path")
            continue
        path = (manifest_path.parent / path_value).resolve()
        if target_dir not in path.parents or path.suffix != ".rs":
            failures.append(f"fuzz/Cargo.toml: {name} must point to fuzz_targets/*.rs")
            continue
        if not path.exists():
            failures.append(f"fuzz/Cargo.toml: registered target missing: {path_value}")
            continue
        registered.add(path)
        source = path.read_text(errors="replace")
        if "fuzz_target!" not in source:
            failures.append(f"{path.relative_to(ROOT)}: registered target does not call fuzz_target!")

    actual = {path.resolve() for path in target_dir.glob("*.rs")}
    for path in sorted(actual - registered):
        failures.append(f"{path.relative_to(ROOT)}: unregistered fuzz target source")
    return failures


def main() -> int:
    failures: list[str] = []
    files_scanned = 0
    for base in SCAN_DIRS:
        if base.exists():
            for rust_file in base.rglob("*.rs"):
                files_scanned += 1
                failures.extend(check_file(rust_file))
    failures.extend(check_crate_roots())
    failures.extend(check_fuzz_target_registration())

    print(f"Static audit scanned {files_scanned} Rust files.")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print("Static audit: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
