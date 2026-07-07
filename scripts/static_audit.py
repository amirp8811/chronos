#!/usr/bin/env python3
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SCAN_DIRS = [ROOT / "crates", ROOT / "tools"]
FAIL_PATTERNS = {
    "unsafe": re.compile(r"\bunsafe\b"),
    "todo_macro": re.compile(r"\btodo!\s*\("),
    "unimplemented_macro": re.compile(r"\bunimplemented!\s*\("),
    "dbg_macro": re.compile(r"\bdbg!\s*\("),
}
WARN_PATTERNS = {
    "unwrap": re.compile(r"\.unwrap\s*\("),
    "expect": re.compile(r"\.expect\s*\("),
    "panic": re.compile(r"\bpanic!\s*\("),
}

# Test modules are allowed to use unwrap/expect/panic more freely.
def in_test_context(text: str, pos: int) -> bool:
    prefix = text[:pos]
    return "#[cfg(test)]" in prefix[-2000:] or "mod tests" in prefix[-2000:]

failures = []
warnings = []
files = []
for base in SCAN_DIRS:
    if base.exists():
        files.extend(base.rglob("*.rs"))

for path in sorted(files):
    text = path.read_text(errors="replace")
    rel = path.relative_to(ROOT)
    for name, pat in FAIL_PATTERNS.items():
        for m in pat.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            failures.append(f"{rel}:{line}: forbidden pattern {name}")
    for name, pat in WARN_PATTERNS.items():
        for m in pat.finditer(text):
            if in_test_context(text, m.start()):
                continue
            line = text.count("\n", 0, m.start()) + 1
            warnings.append(f"{rel}:{line}: review warning {name}")

print(f"Static audit scanned {len(files)} Rust files")
if warnings:
    print("Warnings:")
    for w in warnings:
        print("  " + w)
if failures:
    print("Failures:")
    for f in failures:
        print("  " + f)
    sys.exit(1)
print("Static audit: PASS")
