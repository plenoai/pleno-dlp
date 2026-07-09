# dlp-bench

A reproducible, re-runnable version of [`docs/comparison.md`](../docs/comparison.md)'s
methodology: `make bench` regenerates a synthetic recall corpus, clones a
pinned real-world corpus, runs pleno-dlp / trufflehog / gitleaks against
both, and writes a results table. See issue #298 for the origin story.

## Quick start

```sh
make bench
cat bench/results/results.md
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
- **§4–§8** (noise sweeps, git-history timings, verification triage, PII,
  capability probes): not automated here. Each depends on either a
  larger set of pinned OSS repos and manual FP adjudication (§4), timing
  methodology with statistical machinery (§5, already covered by
  `docs/benchmarks.md`'s own `hyperfine` recipe), or fixtures with no
  fixed ground-truth shape (§6–§8). Deferred — see the PR that introduced
  this directory for the explicit list.

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
  docsync/    regenerates docs/comparison.md's live box from results.json (`go run ./bench/docsync`)
  scripts/    fetch-tools.sh (pinned, checksum-verified tool download),
              check-competitor-drift.sh + bump-competitor-pin.sh (issue #299)
  fixtures/synthetic/   generated output lives here (gitignored)
  results/    results.json / results.md (gitignored)
```

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
