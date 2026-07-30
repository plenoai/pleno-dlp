# dlp-bench

A reproducible, re-runnable version of [`docs/comparison.md`](../docs/comparison.md)'s
methodology: `make bench` regenerates a synthetic recall corpus, clones a
pinned real-world corpus, runs pleno-dlp / trufflehog / gitleaks against
both, and writes a results table. See issue #298 for the origin story.

Recall and throughput comparisons disable remote verification for both
pleno-dlp (`--no-verify`) and TruffleHog (`--no-verification`). This keeps
the benchmark detection-only, avoids provider traffic from synthetic
credentials, and prevents network latency from being attributed to either
scanner's local engine.

## Quick start

```sh
make bench
cat bench/results/results.md

# Git-history performance regression smoke (4,000 commits / 20,000 objects)
make bench-git-history
cat bench/results/git-history.md
```

`bench-fixtures` and `bench-tools` are separate targets so CI can cache
the (network-dependent) tool download apart from the fixture generation;
`make bench` runs both plus the harness. `make bench-offline` skips the
leaky-repo clone if you have no network.

## What this reproduces, and what it doesn't

- **§2 (50-type synthetic recall corpus)**: `bench/gen` generates 48 of
  the 50 types — the ones with a pleno-dlp detector in this repo today
  (or a documented current miss; see below). Left out: `rubygems`
  (pleno-dlp only catches it via the entropy-based `GenericHighEntropy`
  detector, not a deterministic regex — unsuitable for a fixed-format
  fixture that claims a specific detector) and `gcp-service-account-json`
  (a full service-account JSON body is a much larger fixture surface;
  deferred).
- **§3 (leaky-repo real-world recall)**: fully reproduced. Ground truth
  comes from leaky-repo's *own* `.leaky-meta/secrets.csv` — not a label
  file this project authored — so there is nothing here for us to have
  gotten wrong or cherry-picked; see `bench/harness/leakyrepo.go`.
- **§5 (git-history timings)**: reproduced separately by
  `make bench-git-history`; the benchmark and its performance gates are
  described below.
- **§4 and §6–§8** (noise sweeps, verification triage, PII, capability
  probes): not automated here. They depend on pinned OSS corpora plus
  manual FP adjudication, or fixtures without a fixed ground-truth shape.

`make bench`'s numbers are **not** expected to match `docs/comparison.md`
exactly, and that's the point: the doc is a frozen snapshot from
2026-06-10 against pleno-dlp v0.53.0, and detectors keep changing. As one
concrete example found *while building this generator*: `docs/comparison.md`
§2 lists four pleno-dlp misses (`asana-pat`, `azure-storage-account-key`,
`pgp-private-key-block`, `slack-webhook-url`). Running the corpus against
current `HEAD` showed three of those four now caught (`Asana`,
`PrivateKeyPEM`'s PGP-armor branch, `SlackWebhook` all fire) — the
detectors were added or fixed after the doc was captured. `make bench` is
the regression base going forward; `docs/comparison.md` is a citable,
dated snapshot. Nothing in this directory rewrites that doc automatically.

## Structure

```
bench/
  gen/        synthetic-corpus generator (`go run ./bench/gen`)
  labels/     ground-truth manifest schema shared by gen and harness
  harness/    3-tool re-run + recall scoring (`go run ./bench/harness`)
  git-history/ deterministic deep-history fixture + pleno/TruffleHog benchmark
  docsync/    regenerates docs/comparison.md's live box from results.json (`go run ./bench/docsync`)
  scripts/    fetch-tools.sh (pinned, checksum-verified tool download),
              check-competitor-drift.sh + bump-competitor-pin.sh (issue #299)
  fixtures/synthetic/   generated output lives here (gitignored)
  results/    results.json / results.md (gitignored)
```

## Deep Git history performance

`make bench-git-history` builds one deterministic bare repository with
4,000 commits and exactly 20,000 Git objects. The fixture is generated with
`git fast-import` in a temporary directory and is never committed. A single
non-placeholder GitHub token is assembled at runtime, inserted in one commit,
and omitted from result artifacts. Both tools scan the same repository with
only the GitHub detector, verification disabled, and binary/archive skipping
enabled. Every timed scan must report that canary exactly once at the expected
path and commit; a zero-result scan is a benchmark failure.

The harness records direct-source timing windows, their linear throughput
slope, the tail/early throughput ratio, runtime memory counters, and
end-to-end timings for this checkout and the checksum-pinned
`bench/.tools/trufflehog`. The Make targets always refresh and checksum-verify
that pin before measuring. The harness performs warmups and repeated
interleaved samples; fast scans are repeated inside each sample until at least
two seconds have actually elapsed. JSON and Markdown results are written to
`bench/results/git-history.{json,md}`.

The first source window includes process startup and is excluded from the
slope and tail/early gate. Stability compares the median throughput of the
next three windows with the median of the final three, so the large fixture
compares chunks 170,001–200,000 with chunks 10,001–40,000.

Pull requests run the 4,000-commit smoke without enforcing machine-sensitive
timing thresholds. The separate scheduled/manual job runs:

```sh
make bench-git-history-large
```

That opt-in target fixes the fixture at 200,000 commits and exactly 1,000,000
objects, then requires pleno-dlp's median to be at most 90% of TruffleHog's and
the median throughput of the final three source windows to be at least 90% of
the first three post-startup windows. It writes artifacts before returning a
non-zero status when either gate fails.

## Keeping docs/comparison.md current automatically (issue #299)

`.github/workflows/comparison-refresh.yml` runs `make bench` and
`go run ./bench/docsync` on two triggers: a pleno-dlp tag push
(`v*.*.*`), and a daily scheduled check
(`bench/scripts/check-competitor-drift.sh`) for a new trufflehog or
gitleaks release that the pin in `bench/scripts/fetch-tools.sh` doesn't
match yet. On either trigger it opens (or updates) a PR — never pushes
to `main` directly, since a ruleset requires the `test` check and a
review.

`bench/docsync` only rewrites the `<!-- BENCH:AUTO:START -->` /
`<!-- BENCH:AUTO:END -->` box near the top of `docs/comparison.md`:
headline recall counts and tool versions, both mechanically derived
from `results.json`. It never touches §1-§8's prose, audit trail, or
per-file matrices — those came from an adversarial audit process (see
"Reproducing" below) that can't be reconstructed from a boolean
hit/miss JSON, and fabricating that narrative on every run would be
worse than leaving it as the dated snapshot it already documents itself
to be.

When a competitor release is detected, the same run also bumps the pin:
`bench/scripts/bump-competitor-pin.sh <tool> <version>` fetches that
release's own `*_checksums.txt` and rewrites both
`bench/scripts/fetch-tools.sh` and `bench/harness/tools.go` together
(the pair `bench/CONTRIBUTING.md` already requires to move in lockstep
for a manual bump) — no hand-computed checksums, same rule as the
manual process.

## The synthetic corpus: how it avoids becoming what it's testing against

The known failure mode this project has hit before (see CLAUDE.md): a
benchmark corpus with malformed fixtures quietly becomes a fake
competitor gap. Building this generator turned up the mirror-image bug —
a *correctly*-formatted fixture that pleno-dlp's own filters would eat,
which would quietly become a fake pleno-dlp loss. Two safeguards, both
load-bearing (not decorative):

1. Every generated token is checked against `engine.IsPlaceholder` before
   use (`bench/gen/rand.go`'s `token()` helper) — reusing pleno-dlp's own
   placeholder heuristic instead of re-deriving "looks like a real
   secret" independently. This is how the classic
   `AKIAIOSFODNN7EXAMPLE` / `wJalrXUtnFEMI/K7MDENG/...` AWS docs pair got
   ruled out during development: it's on pleno-dlp's own exact-match
   placeholder list (and, separately, on no fewer than all three tools'
   own allowlists — a live probe found `pleno-dlp`, `trufflehog`, and
   `gitleaks` all report **zero** findings on that literal end to end).
2. `bench/gen/spec_test.go`'s `TestFixtures_DetectedByPlenoDLP` drives
   every fixture through the real scan engine (prefilter, detector
   registry, placeholder filter — the same chain `cmd/scan.go` wires) and
   asserts the claimed detector fires. It runs under plain
   `go test ./... -race`, so a future engine change that starts eating a
   fixture breaks CI immediately, not silently.

That second safeguard is also how `azure-storage-account-key` was found
to be a genuine, previously undocumented detector bug rather than a
fixture bug: `pkg/detectors/azurestoragekey/azurestoragekey.go`'s
`connRe` uses `[^;]{0,200}` between the `AccountName=` and `AccountKey=`
fields, which by construction cannot cross the semicolon that always
separates them in Azure's real connection-string format
(`DefaultEndpointsProtocol=...;AccountName=...;AccountKey=...`). The
detector therefore never fires on the one shape Azure actually emits.
This is recorded as a `knownMisses` entry in `bench/gen/spec.go` (so the
self-check test asserts the *miss*, and the results table surfaces it
under "documented pleno-dlp losses" rather than reporting it as a clean
regression) — not fixed here, since fixing a detector is
detector-engineer's scope, not a bench-tooling change's.

## Private holdout

See [`HOLDOUT.md`](HOLDOUT.md).
