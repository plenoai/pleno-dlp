#!/usr/bin/env bash
set -euo pipefail

case_dir="$PLENO_DLP_E2E_ROOT/04-source-failure"
mkdir -p "$case_dir"
missing="$case_dir/does-not-exist"

set +e
"$PLENO_DLP_E2E_BIN" scan --format json --no-verify --quiet \
  git --repo "$missing" >"$case_dir/stdout.json" 2>"$case_dir/stderr.txt"
status=$?
set -e

test "$status" -ne 0
grep -q 'error: init git source' "$case_dir/stderr.txt"
grep -q 'does-not-exist' "$case_dir/stderr.txt"
