#!/usr/bin/env bash
set -euo pipefail

case_dir="$PLENO_DLP_E2E_ROOT/02-stdin-finding"
mkdir -p "$case_dir"
stdout="$case_dir/stdout.json"
stderr="$case_dir/stderr.txt"

set +e
token='xoxb'
token+='-1234567890-1234567890123-a1B2c3D4e5F6g7H8i9J0k1L2'
printf 'slack_token=%s\n' "$token" | \
  "$PLENO_DLP_E2E_BIN" scan --format json --no-verify --fail-on any --quiet \
    stdin --label e2e-stdin >"$stdout" 2>"$stderr"
status=$?
set -e

test "$status" -eq 1
grep -q '"detector": "SlackBotToken"' "$stdout"
grep -q '"type": "stdin"' "$stdout"
grep -q '"label": "e2e-stdin"' "$stdout"
