#!/usr/bin/env bash
# Run the race detector only over packages affected since BASE
# (default origin/main). Usage: scripts/race-affected.sh [BASE] [go test flags...]
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
base="${1:-origin/main}"
shift || true
pkgs=()
while IFS= read -r p; do [ -n "$p" ] && pkgs+=("$p"); done < <(scripts/affected-packages.sh "$base")
if [ "${#pkgs[@]}" -eq 0 ]; then
  echo "race-affected: no Go packages affected since $base"
  exit 0
fi
echo "race-affected: ${#pkgs[@]} package(s) since $base" >&2
go test -race -count=1 -timeout 10m "$@" "${pkgs[@]}"
