# Benchmarks

Engine throughput on synthetic and self-scan workloads. Numbers update
as the engine evolves; tag each row with the commit that produced it
so regressions are bisectable.

## How to reproduce

```sh
# Cold-path engine throughput across worker concurrencies + the
# isolated keyword prefilter cost.
go test -bench=. -benchmem -benchtime=3s -run=Bench ./pkg/engine
```

- `BenchmarkScan_ColdPath` — 1024 chunks × 4 KiB of plain prose with
  no secrets. Every detector pays the prefilter cost; no detector
  fires. Real codebases skew further toward this shape (most files
  have zero secrets), so the cold-path number is the one to optimise.
- `BenchmarkKeywordMatch` — the prefilter in isolation (one lowercase
  pass + one AC walk over the full keyword union).

Hardware-dependent. Record CPU, OS, Go version, and detector count
next to each result so cross-machine comparisons stay honest.

## v0.44.0 — Aho-Corasick keyword prefilter (commit `9fe0daf`)

PR [#107](https://github.com/plenoai/pleno-dlp/pull/107). Replaces the
per-`(detector × variant)` `bytes.ToLower` + `bytes.Contains` loop
with a single Aho-Corasick automaton built once at engine construction
(pattern shared with trufflehog `pkg/ahocorasickcore`, gitleaks rule
groups, ripgrep's AC prefilter).

Apple M3, macOS 25.3, go 1.25.2, all 607 detectors registered.

| Bench | v0.43.0 (before) | v0.44.0 (after) | Δ |
|---|---:|---:|---:|
| `KeywordMatch` MB/s | 1.47 | **45.28** | **30.8×** |
| `KeywordMatch` alloc/op | 12.27 MB | **0 B** | — |
| `KeywordMatch` allocs/op | 655 | **0** | — |
| `ColdPath/conc=1` MB/s | 1.17 | **6.98** | **5.97×** |
| `ColdPath/conc=4` MB/s | 3.79 | **24.95** | **6.58×** |
| `ColdPath/conc=8` MB/s | 4.89 | **32.93** | **6.73×** |
| `ColdPath/conc=16` MB/s | 4.59 | **31.56** | **6.88×** |
| `ColdPath` alloc/op (conc=8) | 2.58 GB | **11.92 MB** | **216×** less |
| `ColdPath` allocs/op (conc=8) | 1.30M | **13.4k** | **94×** fewer |

Raw `go test -bench` output (post-change):

```
goos: darwin
goarch: arm64
pkg: github.com/plenoai/pleno-dlp/pkg/engine
cpu: Apple M3
BenchmarkScan_ColdPath/conc=1-8         5    600904975 ns/op    6.98 MB/s   11550153 B/op    13386 allocs/op
BenchmarkScan_ColdPath/conc=4-8        22    168120714 ns/op   24.95 MB/s   11857881 B/op    13669 allocs/op
BenchmarkScan_ColdPath/conc=8-8        27    127376537 ns/op   32.93 MB/s   11921627 B/op    13763 allocs/op
BenchmarkScan_ColdPath/conc=16-8       27    132910412 ns/op   31.56 MB/s   11884905 B/op    13718 allocs/op
BenchmarkKeywordMatch-8              7772       424056 ns/op   45.28 MB/s          0 B/op        0 allocs/op
```

End-to-end CLI smoke (`pleno-dlp scan filesystem .` against this
repository, 1.3k files, all detectors): **1.77 s wall, 5.60 s CPU**
on 8 cores (`322 %` CPU utilisation — workers are no longer
serialised on lock-stepped allocator pressure).

### What changed

- `pkg/ahocorasick` — small in-repo case-sensitive AC matcher
  (~200 LOC, zero new module deps).
- `pkg/engine` — engine constructor builds the prefilter once;
  `scanChunkLeaf` lower-cases each variant once into a pooled buffer,
  walks AC, dispatches only the detectors a keyword unlocked.
  `isVerifier` cached at construction time.

### Comparison to other OSS

| Tool | Strategy | Notes |
|---|---|---|
| **trufflehog** | `pkg/ahocorasickcore` — single AC over lower-cased keywords | Same pattern, slightly larger surface (output filtering integrated). |
| **gitleaks** | Pre-grouped regexps by literal prefix | Per-rule regex; effective on small rulesets, doesn't scale to 600+ detectors as cleanly. |
| **ripgrep** | Aho-Corasick crate; Teddy SIMD for ≤8 patterns | Sets the bar for fixed-string set search. AC is the right default until alloc + scalar costs are gone. |

### Follow-ups

- Pool `decoder.Variants` output slice and decoded buffers for
  archive- / base64-heavy inputs (measure first).
- Evaluate Teddy-style SIMD AC only after AC + lowercase drops below
  ~5 % of the engine's hot path. Today it's well above that and the
  scalar AC is the right tool.

## Pre-v0.44.0 baseline (commit `e90660c`)

Same hardware / Go / detector count as above. Captured to make the
delta in the v0.44.0 row reproducible.

```
BenchmarkScan_ColdPath/conc=1-8         1   3576366709 ns/op    1.17 MB/s   2542360440 B/op   1302107 allocs/op
BenchmarkScan_ColdPath/conc=4-8         3   1105748125 ns/op    3.79 MB/s   2589490090 B/op   1344509 allocs/op
BenchmarkScan_ColdPath/conc=8-8         4    857848594 ns/op    4.89 MB/s   2580744538 B/op   1336723 allocs/op
BenchmarkScan_ColdPath/conc=16-8        4    914684136 ns/op    4.59 MB/s   2578107732 B/op   1333931 allocs/op
BenchmarkKeywordMatch-8               184     13077450 ns/op    1.47 MB/s   12268301 B/op        655 allocs/op
```
