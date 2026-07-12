# ADR-0003 — SaaS connectors as humble objects, no unit tests (2026-05-10)

**Status:** Accepted. Owner: architect. Supersedes the unit-test
expectations implied by the now-deleted `pkg/connectors/<name>/<name>_test.go`
files that lived under ADR-0001.

## Context

The connector refactor in v0.38.0 collapsed each SaaS provider from a
3-4-file subpackage (`<name>.go`, `client.go`, `pagination.go`,
`<name>_test.go`) into a single Lambda-handler-shape file at
`pkg/connectors/<name>.go`. The new contract is a flat
`Connector{SourceType, Scan, Verify, Revoke}` value registered in
`init()`; the `SaaSConnector` interface, `Descriptor`, `Capability`
bitmask, `AuthMode` enum, and per-connector `Init` method that ADR-0001
prescribed are all gone.

Roughly 2,900 LoC of per-connector tests (~63 test functions across 7
provider files) were deleted alongside the old subpackages. The
question this ADR resolves: do those tests come back, in what form, and
how much new test code do we owe to v0.38.0 to call the refactor done?

## Decisions

### D1. Connectors are humble objects; no unit tests for them

Each connector file is, by construction:

```go
func scanX(ctx, cfg, emit) error {
    // 1. Validate cfg (5-10 lines of `if x == "" return err`)
    // 2. HTTP loop with cursor pagination (15-30 lines around net/http)
    // 3. emit(data, metadata) per item
    return nil
}
```

There is no algorithm, no state machine, no domain logic. The code is
**HTTP / JSON orchestration around an upstream API we do not control**.
Per Michael Feathers' humble object pattern, the value of unit tests on
this surface is bounded by:

- "the `==` operator works" (config validation)
- "Go's `for` keyword iterates" (pagination loops)
- "`switch resp.StatusCode` dispatches" (verify endpoints)
- "`init()` ran at process start" (registry tests)

Mocking the upstream API with `httptest.Server` and asserting our own
`for` loop matches our own mock proves we wrote consistent code on both
sides of the test boundary, not that the connector works against the
real API. When the real API breaks (rotation policy change, schema
revision, deprecation), mock-server tests pass cleanly while production
breaks — the worst possible failure mode.

We therefore do **not** restore the deleted per-connector unit tests
and do **not** add new ones for `pkg/connectors/<name>.go`.

### D2. Algorithmic logic lives in helper sub-packages, with their own tests

The algorithms that warrant unit tests are isolated from the humble
HTTP layer:

| Helper                                     | Owns                              | Tests             |
|--------------------------------------------|-----------------------------------|-------------------|
| `pkg/connectors/notion/markdown/`          | Notion block JSON → Markdown      | `converter_test.go` |
| `pkg/connectors/jira/adf/`                 | Atlassian Document Format → text  | `converter_test.go` |
| `pkg/connectors/jira/storage/`             | Jira XHTML storage format → text  | `parser_test.go`    |
| `pkg/connectors/confluence/storage/`       | Confluence XHTML → text           | `parser_test.go`    |

These tests survive the refactor untouched and continue to cover the
real bug surface. New parsers (a future Linear, Asana, Discord
connector that needs format normalisation) follow the same split:
parser sub-package with unit tests, connector file calls the parser
without testing it.

### D3. Verification is real-world, not mock-server

Connector regressions are caught by:

- **Smoke runs** post-release: `pleno-dlp scan github --org <self>`,
  one invocation per provider, before the tag is announced. ~30 seconds
  per provider against a live account.
- **fp-reduction-loop skill** (CLAUDE.md): runs `gh-verify` against
  trending GitHub repos discovered via OSSInsight. A connector that
  silently mis-paginates or drops blobs surfaces as anomalous finding
  counts vs. baseline.
- **CI race-clean suite** (`go test ./... -race`): proves concurrency
  safety across the engine + helper packages, which is the property
  most likely to regress under refactor.

The 30 seconds of operator attention at release time outperforms 1,800
LoC of mocks for the regressions that actually matter.

### D4. The framework itself does not need tests

`Register` / `Get` / `Names` / `AsSource` in
`pkg/connectors/connectors.go` are a `sync.RWMutex` over a `map[string]Connector`
plus a 30-line adapter that wraps a `Connector` as a `sources.Source`.
Testing this is testing Go's stdlib map and stdlib mutex behaviour.
The adapter's correctness is asserted transitively: the engine drives
`sources.Source` for filesystem/git/stdin every time `go test ./...`
runs, and the same code path drives connector chunks once the CLI
wires one up — exercised by the smoke runs above.

## Consequences

- Net test count: 4241 race-clean tests across 622 packages (no
  change). 4304 → 4241 in v0.38.0 was the deletion of the per-connector
  white-box files; this ADR confirms they are not coming back.
- Future connector PRs do **not** ship `<name>_test.go`. PR authors
  add unit tests only when their connector introduces a new helper
  sub-package with genuine logic to verify.
- The release checklist gains an explicit "smoke each migrated
  connector against a live account" step in lieu of the lost CI
  coverage. (Tracked separately; not part of this ADR.)
- Reviewers who ask "why is there no test for this PR?" should be
  pointed at this ADR.

## References

- [`_workspace/architecture-decisions.md`](../../_workspace/architecture-decisions.md)
  — ADR-0001, the original connector contract this ADR partially
  supersedes (D1/D2 still hold for the engine→Chunk mapping; D3/D4
  superseded by the v0.38.0 framework slim-down).
- [`CHANGELOG.md`](../../CHANGELOG.md) — `[0.38.0]` entry documenting
  the refactor and the deletion of the per-connector test files.
- Michael Feathers, *Working Effectively with Legacy Code*, ch. 23
  ("Humble Object" pattern) — the principle this ADR applies.
