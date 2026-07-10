#!/usr/bin/env bash
set -euo pipefail

case_dir="$PLENO_DLP_E2E_ROOT/01-filesystem-success"
mkdir -p "$case_dir"
printf '%s\n' 'aws_access_key_id=AKIA7M4Q2W9R6T3Y8U1I' > "$case_dir/aws.env"

out=$(
  "$PLENO_DLP_E2E_BIN" scan --format json --no-verify --fail-on critical --quiet \
    filesystem "$case_dir"
)
grep -q '"detector": "AWS"' <<<"$out"
grep -q '"type": "filesystem"' <<<"$out"
grep -q '"path":' <<<"$out"
