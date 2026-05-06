---
name: qa-cross-boundary
description: Validate correctness across detector, source, engine, and output boundaries — interface compatibility, chunk metadata propagation, race-detector cleanliness, and end-to-end CLI scenarios. qa agent only. Use immediately after a detector or source integrates, after interface changes, or when a regression is suspected.
---

# qa-cross-boundary

## Purpose

Move past "does it exist" and verify the seams: each module compiles in isolation, but the bugs live where modules meet. This skill targets those seams.

## Validation matrix

| ID | Boundary | Method | Cadence |
|---|---|---|---|
| B1 | Detector interface | every detector satisfies `Detector` via a `var _ detectors.Detector = (*Scanner)(nil)` compile-time guard | on detector add/edit |
| B2 | Source interface | every source satisfies `Source` analogously | on source add/edit |
| B3 | Chunk → detector prefilter | for each source's representative fixture, at least one detector's keywords match (otherwise the source is emitting "meaningless" data, or the fixture is wrong) | on source add |
| B4 | Result → output | every emitted Result field (Type, Verified, Raw redacted, RawV2, Redacted, ExtraData) survives JSON, SARIF, and table output | on detector or output change |
| B5 | Metadata propagation | source-populated metadata reaches output (especially SARIF locations) | on source or output change |
| B6 | Race | `go test ./... -race -count=1` is clean | every PR |
| B7 | e2e CLI | five testdata scenarios (filesystem with AWS, git with GH PAT, github mock with Slack, etc.) match expected output | every PR |
| B8 | Verify fallback | each detector's Verify behaves correctly under mocked 200/401/429/timeout | on Verify change |

## Procedures

### 1. Interface conformance (B1, B2)

```bash
go build ./...
go vet ./...
```

Hunt for missing compile-time guards:

```bash
rg -L 'var _ (detectors\.Detector|sources\.Source)' pkg/detectors pkg/sources
```

When missing, SendMessage the owner and TaskCreate.

### 2. Keyword prefilter (B3)

Walk each source's fixture chunks and count keyword hits per detector. Any source whose fixtures hit zero keywords means the fixture is not a real signal — fix the fixture.

```go
// tests/integration/prefilter_test.go
for _, src := range sourceFixtures {
    chunks := src.collectChunks(t)
    for _, det := range registry.All() {
        hits := countKeywordHits(chunks, det.Keywords())
        if hits == 0 && expected[src.Type()][det.Type()] {
            t.Errorf("%s/%s: expected keyword hits, got 0", src.Type(), det.Type())
        }
    }
}
```

### 3. Result / metadata propagation (B4, B5)

Pick one canonical fixture and assert:
- every Result field maps 1:1 to JSON output
- SARIF `locations[0].physicalLocation` originates from source metadata

```go
got := runScan(t, "testdata/git-with-ghpat")
require.Equal(t, "GitHub", got.Results[0].DetectorType)
require.NotEmpty(t, got.Results[0].Source.Git.Commit)
require.NotEmpty(t, got.Results[0].Source.Git.File)
```

### 4. Race (B6)

```bash
go test ./... -race -count=1 -timeout 5m
```

Flaky tests are recorded in `_workspace/flaky-tests.md` and prioritised for repair.

### 5. e2e CLI (B7)

`tests/e2e/` hosts shell-driven scenarios:

```bash
# tests/e2e/01_filesystem_aws.sh
set -euo pipefail
out=$(./bin/pleno-dlp filesystem testdata/aws-key/ --json --no-verification)
echo "$out" | jq -e '.[] | select(.detector_type=="AWS")' > /dev/null
```

### 6. Verify mocks (B8)

`pkg/common/httpclient/testserver.go` provides a mock helper. Every detector's `_verify_test.go` exercises 200 / 401 / 429 / timeout.

## Regression report format

`_workspace/qa-report-<YYYY-MM-DD>.md`:

```markdown
## Regression: <one-line summary>

- Scenario: <input/condition>
- Expected: <expected outcome>
- Actual: <what happened, with snippet>
- Affected modules: pkg/...
- Reproducer: `go test ./pkg/.../  -run Test...` or `./bin/pleno-dlp ...`
- Suspected root cause: <interface mismatch / metadata loss / race / other>
- Owner: @<agent>
```

## Operating principles

1. **No auto-fixes.** Detect, reproduce, report — fixing belongs to the owner.
2. **Flaky tracking.** A test failing 1-of-3 immediately enters `_workspace/flaky-tests.md`; never silently rerun.
3. **No real API calls.** Verify always runs against the mock server. Real tokens are forbidden.
4. **Incremental.** Validate as soon as a module integrates. Sweeping at the end balloons the cost of attribution.

## When prior artifacts exist

Read the latest five `_workspace/qa-report-*.md` and `_workspace/flaky-tests.md` first, and check whether the same patterns are recurring. Repeated regressions warrant an ADR root-cause request.
