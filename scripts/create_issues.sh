#!/usr/bin/env bash
# Turn open items in docs/FULL_TODO.md into GitHub Issues.
#
# Open items are lines starting with `- [todo]`, `- [partial]`, or
# `- [external]`. Items marked `- [done]` are skipped. The nearest
# `##`/`###` section header is used as an area prefix in the issue title.
#
# Requires the `gh` CLI authenticated. By default this runs in DRY-RUN
# mode and only prints what it would create. Set CREATE_ISSUES=1 to
# actually create the issues (run from the repo root).
set -euo pipefail
cd "$(dirname "$0")/.."

TODO=docs/FULL_TODO.md
[ -f "$TODO" ] || { echo "missing $TODO" >&2; exit 1; }

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI not found -> DRY-RUN mode."
  DRY=1
elif [ "${CREATE_ISSUES:-0}" != "1" ]; then
  echo "DRY-RUN (gh present but CREATE_ISSUES != 1). Set CREATE_ISSUES=1 to create."
  DRY=1
else
  DRY=0
fi

section="general"
count=0
while IFS= read -r line; do
  if [[ "$line" =~ ^(##+|#)\  ]]; then
    section="${line#* }"
    continue
  fi
  if [[ "$line" =~ ^-\ \[(todo|partial|external)\]\ ?(.*) ]]; then
    text="${BASH_REMATCH[2]}"
    [ -z "$text" ] && continue
    title="[${section}] ${text}"
    if [ "$DRY" = "1" ]; then
      echo "[DRY] $title"
    else
      gh issue create --title "$title" \
        --body "Source: $TODO (section: $section)" >/dev/null \
        && count=$((count + 1)) \
        || echo "FAILED: $title" >&2
    fi
  fi
done < "$TODO"

if [ "$DRY" = "1" ]; then
  echo "Dry run complete. Re-run with CREATE_ISSUES=1 (and authenticated gh) to create issues."
else
  echo "Created $count issue(s)."
fi
