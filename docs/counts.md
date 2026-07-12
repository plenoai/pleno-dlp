# Published counts: definitions and single source of truth

Four numbers get quoted repeatedly across README.md, website/index.html,
docs/comparison.md, and docs/verify-coverage.md: pleno-dlp's detector
count, pleno-dlp's source count, and the two competitor counts
(trufflehog detectors, gitleaks rules). This page defines exactly what
each one counts and where it comes from. `pkg/detectors/counts_test.go`
(and, for the source count, `cmd/pleno-dlp/cmd/sources_sync_test.go`)
enforces every claim listed below against these definitions — including
the "Current value" lines on this page itself. Both run under plain
`go test ./...`, so CI fails on any drift automatically.

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

## 2. pleno-dlp source count — runtime-derived

**What is counted:** entries in `pkg/sources/catalog.All()` — the union
of the core-source registry (`sources.Register`) and the SaaS-connector
registry (`connectors.Register`) — that have a wired `scan` subcommand.
This is the same list `pleno-dlp sources list` prints, with the
`CLI-WIRED` column marking the split. Registered-but-planned connectors
(currently elasticsearch #217, jenkins #218, postman #219, enumerated in
`sources_sync_test.go`'s `plannedSources`) are excluded from the
published count.

**docs/comparison.md's "Scan sources" table cell is the canonical
text.** `cmd/pleno-dlp/cmd/sources_sync_test.go` fails CI when that cell
disagrees with the registry in either direction, and
`pkg/detectors/counts_test.go` cross-checks every other file that quotes
it, including this page.

**Current value:** 28 wired sources.

**Where it's quoted:** website/index.html (hero line), docs/comparison.md
(§1 capability table, §9 prose).

**When this legitimately changes:** when a source or connector
subcommand ships or is removed; update `plannedSources` and
docs/comparison.md in the same PR.

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
