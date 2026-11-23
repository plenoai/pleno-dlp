#!/usr/bin/env bash
set -euo pipefail

# RACE_BASE (main push: the previous main tip) narrows the race run to the
# packages affected since that commit. Unset (tag release) runs every package.
if [ -n "${RACE_BASE:-}" ] && [ "${RACE_BASE}" != "0000000000000000000000000000000000000000" ]; then
  exec bash scripts/race-affected.sh "$RACE_BASE" -timeout 5m
fi
go test ./... -race -count=1 -timeout 5m
