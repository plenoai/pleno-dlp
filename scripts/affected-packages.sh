#!/usr/bin/env bash
# Print the Go packages affected by changes since BASE: packages containing a
# changed file plus every package that transitively imports one. Prints "./..."
# when module-wide inputs change (go.mod, go.sum, unknown base). Includes
# uncommitted and untracked changes so it works before committing.
set -euo pipefail

base="${1:-origin/main}"
module="$(go list -m)"

if ! git rev-parse --verify --quiet "${base}^{commit}" >/dev/null; then
  echo "./..."
  exit 0
fi

changed="$( { git diff --name-only "$base" --; git ls-files --others --exclude-standard; } | sort -u)"
[ -z "$changed" ] && exit 0

if grep -qxE 'go\.(mod|sum)' <<<"$changed"; then
  echo "./..."
  exit 0
fi

# Directories holding changed Go-relevant files (testdata counts for its parent package).
dirs="$(grep -E '\.(go|c|h|s)$|/testdata/' <<<"$changed" \
  | sed -E 's#/testdata/.*##; s#/[^/]*$##; s#^[^/]*$#.#' | sort -u || true)"
[ -z "$dirs" ] && exit 0

seeds=""
for d in $dirs; do
  [ -d "$d" ] || continue
  pkg="$(go list "./$d" 2>/dev/null || true)"
  [ -n "$pkg" ] && seeds+="$pkg"$'\n'
done
[ -z "$seeds" ] && exit 0

go list -f '{{.ImportPath}} {{join .Deps " "}} {{join .TestImports " "}} {{join .XTestImports " "}}' ./... \
  | SEEDS="$seeds" awk '
      BEGIN { n = split(ENVIRON["SEEDS"], s, "\n"); for (i = 1; i <= n; i++) if (s[i] != "") want[s[i]] = 1 }
      { for (i = 1; i <= NF; i++) if ($i in want) { print $1; next } }' \
  | sed "s#^${module}#.#" | sort -u
