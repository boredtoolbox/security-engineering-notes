#!/usr/bin/env bash
# Regenerates README.md as a table of contents linking every Markdown file in the repo.
set -euo pipefail
cd "$(dirname "$0")/.."

{
  echo "# Security Engineering Notes"
  echo
  echo "## Contents"
  echo
  find . -name '*.md' -not -path './README.md' -not -path './.git/*' -not -path './.github/*' \
    | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r f; do
      title=$(grep -m1 '^# ' "$f" | sed 's/^# //' || true)
      [ -n "$title" ] || title="$f"
      echo "- [$title](${f// /%20})"
    done
} > README.md
