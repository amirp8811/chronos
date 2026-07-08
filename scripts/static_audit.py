#!/usr/bin/env python3
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SCAN_DIRS = [ROOT / "crates", ROOT / "tools"]
# Designated crates allowed to use unsafe
UNSAFE_ALLOWED_CRATES = ["chronos-sys-dataplane"]

FAIL_PATTERNS = {
    "unsafe": re.compile(r"\bunsafe\b"),
}

def is_unsafe_allowed(rel_path: Path) -> bool:
    for crate in UNSAFE_ALLOWED_CRATES:
        if f"crates/{crate}" in str(rel_path):
            return True
    return False

def check_file(path: Path):
    text = path.read_text(errors="replace")
    rel = path.relative_to(ROOT)
    failures = []
    
    # We check for the forbidden 'unsafe' keyword
    if not is_unsafe_allowed(rel):
        for m in FAIL_PATTERNS["unsafe"].finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            line_text = text.splitlines()[line-1]
            # Allow safety comments or deny attributes
            if "deny(unsafe_code)" in line_text or "unsafe_code" in line_text:
                continue
            failures.append(f"{rel}:{line}: forbidden 'unsafe' usage outside HAL")
            
    return failures

if __name__ == "__main__":
    all_failures = []
    files_scanned = 0
    for base in SCAN_DIRS:
        if base.exists():
            for rs_file in base.rglob("*.rs"):
                files_scanned += 1
                all_failures.extend(check_file(rs_file))
                
    print(f"Static audit scanned {files_scanned} Rust files.")
    if all_failures:
        for f in all_failures:
            print(f"FAIL: {f}")
        sys.exit(1)
    print("Static audit: PASS")
