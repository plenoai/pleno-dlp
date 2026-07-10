#!/usr/bin/env bash
set -euo pipefail

case_dir="$PLENO_DLP_E2E_ROOT/05-git-metadata"
repo="$case_dir/repo"
mkdir -p "$repo"
git -C "$repo" init -q
git -C "$repo" config user.name 'E2E Test'
git -C "$repo" config user.email 'e2e@example.invalid'
printf '%s\n' 'token=ghp_Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3h2' > "$repo/leak.txt"
git -C "$repo" add leak.txt
GIT_AUTHOR_DATE='2026-01-01T00:00:00Z' GIT_COMMITTER_DATE='2026-01-01T00:00:00Z' \
  git -C "$repo" -c core.hooksPath=/dev/null commit -q -m 'add deterministic fixture'

set +e
"$PLENO_DLP_E2E_BIN" scan --format json --no-verify --fail-on any --quiet \
  git --repo "$repo" >"$case_dir/stdout.json" 2>"$case_dir/stderr.txt"
status=$?
set -e

test "$status" -eq 1
grep -q '"detector": "GitHub"' "$case_dir/stdout.json"
grep -q '"type": "git"' "$case_dir/stdout.json"
grep -q '"file": "leak.txt"' "$case_dir/stdout.json"
grep -Eq '"commit": "[0-9a-f]{40}"' "$case_dir/stdout.json"
