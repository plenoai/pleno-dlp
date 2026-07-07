# Published counts: definitions and single source of truth

Four numbers get quoted repeatedly across README.md, website/index.html,
docs/comparison.md, and docs/verify-coverage.md: pleno-dlp's detector
count, pleno-dlp's source count, and the two competitor counts
(trufflehog detectors, gitleaks rules). This page defines exactly what
each one counts and where it comes from. `pkg/detectors/counts_test.go`
enforces every claim listed below against these definitions — it runs
under plain `go test ./...`, so CI fails on any drift automatically.

## 1. pleno-dlp detector types — runtime-derived

**What is counted:** the number of `detectors.Detector` values returned
by `detectors.All()` once every provider package is blank-imported
(`pkg/detectors/all`). This is the exact registry `pleno-dlp detectors
list` and the scan engine use — it cannot drift from what a released
binary actually scans for, only from what the docs claim it scans for.

It includes both secret detectors and the two PII detector types
(`PIIAnonymize`, `PIIOpenAIPF`); it does not include the four
infrastructure packages under `pkg/detectors/` (`all`, `contextextract`,
`custom`, `verifycoverage`), which are not registered detector types.

Sub-split: of that total, the ones satisfying `detectors.Verifier`
("verified" / live-verification-capable) vs. the rest
("unverified-by-design", see docs/verify-coverage.md's class-b list).

**Current value:** 619 total (552 verified, 67 unverified-by-design).

**Where it's quoted:** README.md ("N built-in detector types"),
website/index.html (meta description, og:description, hero line, the
"02 verify" step, the bench section's pleno-dlp tag), docs/comparison.md
(the coverage-counts table, the "Live-verification capable" cell, and
the detector-breadth prose in §9), docs/verify-coverage.md (the prose
total, the (a)/(b) section headings, and the machine block).

**When this legitimately changes:** every time a detector is added or
removed. The test will fail on the very next `go test ./...` until every
quoted location above is updated in the same PR — that's the intended
gate, not a bug.

## 2. pleno-dlp source count — hand-maintained, not runtime-derived

**What is counted:** distinct data sources pleno-dlp can scan —
filesystem, git, stdin, sqldump, gcs, s3, docker-image, and the SaaS
connectors (GitHub, GitLab, Bitbucket, Slack, Notion, Confluence, Jira,
CircleCI, Datadog, BigQuery, HuggingFace, Redash, Splunk, …).

Unlike detectors, there is no single runtime registry unifying these:
the six types in `pkg/sources` self-register via `sources.Register`,
but the SaaS connectors are wired as ad hoc cobra subcommands
(`cmd/pleno-dlp/cmd/*_cmd.go`) plus a handful of `pkg/connectors`
packages. Deriving this count mechanically would require a source
registry parallel to `pkg/detectors`' — worth doing if the count keeps
drifting, but out of scope for this fix (tracked as a follow-up).

Until that registry exists, **docs/comparison.md's "Scan sources"
table cell is the canonical text**, and every other file must match it
verbatim. `docs/comparison.md` itself is cross-checked internally (the
table cell vs. the §9 prose sentence).

**Current value:** 24 (see docs/comparison.md §1 and §9 for the list).

Note: docs/comparison.md's own source-breadth prose (§9) still lists
docker-image, GCS, HuggingFace, and CircleCI as "planned" (#215, #216,
#220, #221) even though `cmd/pleno-dlp/cmd/{docker,gcs,huggingface,circleci}_cmd.go`
already implement them — the 24 figure and that roadmap paragraph look
stale relative to what has actually shipped. Confirming the true current
source count and refreshing that paragraph is a larger audit than this
fix and is called out separately rather than guessed at here.

**Where it's quoted:** website/index.html (hero line only).

## 3. Competitor counts — dated point-in-time measurements

**What is counted:** trufflehog's detector-package count (870) and
gitleaks's `[[rules]]` count (222), as measured against specific
released tags (trufflehog 3.95.5, gitleaks 8.30.1) per
docs/comparison.md's methodology section. These are not derived from
anything in this repo and cannot be recomputed by a Go test — they
require running/inspecting a third-party binary.

**docs/comparison.md is the canonical source.** Every other place that
quotes these numbers (currently: website/index.html's bench section)
must match docs/comparison.md's table values *and* must say when they
were measured, since a competitor's own detector count moves on its own
schedule, independent of anything pleno-dlp does. The measurement date
is itself extracted from docs/comparison.md's own methodology sentence
("produced by running the three tools side by side on YYYY-MM-DD") and
the test asserts that date string appears in website/index.html
wherever the competitor counts are quoted.

**Current value:** trufflehog 870, gitleaks 222, measured 2026-06-10.

## Adding a new published count

If you add a new spot that quotes one of these numbers, add a
`checkInt`/`checkContains` assertion for it in
`pkg/detectors/counts_test.go` in the same PR — an unenforced count is
exactly the drift this page exists to prevent.
