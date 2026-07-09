# dlp-bench (issue #298): reproduces docs/comparison.md's methodology as
# a runnable target instead of a frozen snapshot. See bench/README.md.
#
# `make bench` is the one command a third party needs; the finer-grained
# targets exist so CI can cache the tool-download step separately from
# the (network-dependent) leaky-repo clone.

.PHONY: bench bench-fixtures bench-tools bench-run bench-offline bench-clean bench-docsync

# Full reproduction: fresh fixtures, pinned tool binaries, live 3-tool
# re-run against both the synthetic and leaky-repo corpora.
bench: bench-fixtures bench-tools bench-run

# Generates the synthetic recall corpus fresh every run (bench/gen) —
# fixtures are never committed, see bench/README.md.
bench-fixtures:
	go run ./bench/gen -out bench/fixtures/synthetic/generated

# Downloads trufflehog + gitleaks at the versions pinned in
# bench/harness/tools.go (checksum-verified). Skipped automatically by
# the harness if both are already on $PATH.
bench-tools:
	bash bench/scripts/fetch-tools.sh

bench-run:
	go run ./bench/harness

# Offline variant: skips the leaky-repo clone (needs network) — useful
# for iterating on the synthetic corpus without a network round-trip.
bench-offline:
	go run ./bench/harness -skip-leaky-repo

bench-clean:
	rm -rf bench/fixtures/synthetic/generated bench/fixtures/synthetic/labels.json bench/.cache bench/.tools bench/results/*.json bench/results/*.md

# Regenerates docs/comparison.md's "Live re-measurement" box from
# bench/results/results.json (issue #299) — run after `make bench`.
# .github/workflows/comparison-refresh.yml is the automated caller;
# this target is the equivalent local reproduction step.
bench-docsync:
	go run ./bench/docsync -trigger "local run ($$(date -u +%Y-%m-%dT%H:%M:%SZ))"
