#!/usr/bin/env bash
set -euo pipefail

case_dir="$PLENO_DLP_E2E_ROOT/03-malformed-archive"
mkdir -p "$case_dir"
printf 'PK\003\004' > "$case_dir/broken.zip"

# Strict mode: a policy-limited archive skip still fails the scan.
set +e
"$PLENO_DLP_E2E_BIN" scan --format json --no-verify --quiet --fail-on-coverage=any \
  filesystem "$case_dir/broken.zip" >"$case_dir/stdout.json" 2>"$case_dir/stderr.txt"
status=$?
set -e

test "$status" -ne 0
grep -q 'scan coverage incomplete' "$case_dir/stderr.txt"
grep -q 'archive' "$case_dir/stderr.txt"

# Default mode (--fail-on-coverage=gap): the corrupt archive is reported as a
# policy skip and does not affect the exit code.
set +e
"$PLENO_DLP_E2E_BIN" scan --format json --no-verify --quiet \
  filesystem "$case_dir/broken.zip" >"$case_dir/stdout-default.json" 2>"$case_dir/stderr-default.txt"
status=$?
set -e

test "$status" -eq 0
grep -q 'coverage: status=ok' "$case_dir/stderr-default.txt"
grep -q 'skipped_by_policy=1' "$case_dir/stderr-default.txt"
grep -q 'coverage: entry severity=policy-skip kind=archive' "$case_dir/stderr-default.txt"
