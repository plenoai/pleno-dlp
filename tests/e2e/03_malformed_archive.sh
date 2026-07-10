#!/usr/bin/env bash
set -euo pipefail

case_dir="$PLENO_DLP_E2E_ROOT/03-malformed-archive"
mkdir -p "$case_dir"
printf 'PK\003\004' > "$case_dir/broken.zip"

set +e
"$PLENO_DLP_E2E_BIN" scan --format json --no-verify --quiet \
  filesystem "$case_dir/broken.zip" >"$case_dir/stdout.json" 2>"$case_dir/stderr.txt"
status=$?
set -e

test "$status" -ne 0
grep -q 'scan coverage incomplete' "$case_dir/stderr.txt"
grep -q 'archive' "$case_dir/stderr.txt"
