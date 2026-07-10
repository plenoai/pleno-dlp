#!/usr/bin/env bash
set -euo pipefail

# Build the test binary first so Getrusage measures the scanner fixture,
# not the Go compiler.
bin="$(mktemp -t pleno-github-bench.XXXXXX)"
out="$(mktemp -t pleno-github-bench-out.XXXXXX)"
trap 'rm -f "$bin" "$out"' EXIT
go test -c -o "$bin" ./pkg/connectors
status=0
PLENO_RUN_LARGE_ORG_BENCH=1 "$bin" -test.run '^TestGitHubLargeOrgBenchmark$' -test.count=1 -test.v >"$out" 2>&1 || status=$?
cat "$out"
exit "$status"
