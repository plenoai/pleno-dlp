#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
workdir=$(mktemp -d "${TMPDIR:-/tmp}/pleno-dlp-e2e.XXXXXX")
trap 'rm -rf "$workdir"' EXIT

export PLENO_DLP_E2E_ROOT="$workdir"
export PLENO_DLP_E2E_BIN="$workdir/pleno-dlp"

cd "$repo_root"
go build -trimpath -o "$PLENO_DLP_E2E_BIN" ./cmd/pleno-dlp

for scenario in tests/e2e/[0-9][0-9]_*.sh; do
  echo "e2e: $scenario"
  bash "$scenario"
done
