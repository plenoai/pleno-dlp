# Published counts: definitions and single source of truth

Two runtime counts get quoted repeatedly across README.md, website/index.html,
and docs/verify-coverage.md: pleno-dlp's detector count and source count.
This page defines exactly what each one counts and where it comes from.
`pkg/detectors/counts_test.go` and
`cmd/pleno-dlp/cmd/sources_sync_test.go` enforce the claims below against
the registries — including the "Current value" lines on this page itself.
Both run under plain `go test ./...`, so CI fails on any drift automatically.

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

**Current value:** 615 total (548 verified, 67 unverified-by-design).

**Where it's quoted:** README.md ("N built-in detector types"),
website/index.html (meta description, og:description, hero line, and the
"02 verify" step), and docs/verify-coverage.md (the prose total, the
(a)/(b) section headings, and the machine block).

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

**This page's "Current value" line is the canonical text.**
`cmd/pleno-dlp/cmd/sources_sync_test.go` fails CI when that value disagrees
with the registry in either direction, and `pkg/detectors/counts_test.go`
cross-checks the public website and README claims.

**Current value:** 28 wired sources.

**Where it's quoted:** website/index.html (hero line).

**When this legitimately changes:** when a source or connector
subcommand ships or is removed; update `plannedSources` and this page in
the same PR.

## Adding a new published count

If you add a new spot that quotes one of these runtime counts, add a
`checkInt`/`checkContains` assertion for it in
`pkg/detectors/counts_test.go` in the same PR — an unenforced count is
exactly the drift this page exists to prevent.
