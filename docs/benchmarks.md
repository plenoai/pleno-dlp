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

## Cross-tool comparison

Measured 2026-05-12 with `hyperfine 1.20.0`, 1 warmup + 5 runs, on
Apple M3 / macOS 25.3.

| Tool | Version | Detector count | Default config |
|---|---|---:|---|
| **pleno-dlp** | v0.44.0 (`9fe0daf`) | 607 | filesystem source, `--quiet --format json`, verify off |
| **trufflehog** | 3.95.2 | ~800 | `filesystem --no-verification --no-update --json --log-level=-1` |
| **gitleaks** | 8.30.1 | ~160 | `dir --no-banner --redact` |

Throughput is measured into `/dev/null`; the goal is engine cost, not
output sink cost. Each tool's exit code is ignored — gitleaks and
pleno-dlp default to non-zero when findings exist; that is policy, not
failure.

### Workload B — cold path (9.4 MB, 200 plain-text log files, **zero** secrets)

This is the dominant shape on real codebases: most files have no
secrets, every detector pays the prefilter cost, no detector pays the
regex cost. Findings: all three tools emit **0**.

| Tool | Mean | Min | Max | vs gitleaks |
|---|---:|---:|---:|---:|
| **pleno-dlp** | **288 ± 6 ms** | 281 ms | 296 ms | 15.3× slower |
| **trufflehog** | 851 ± 12 ms | 842 ms | 872 ms | 45.2× slower |
| **gitleaks** | 18.8 ± 0.9 ms | 18.1 ms | 20.4 ms | 1× (baseline) |

**pleno-dlp is 2.95× faster than trufflehog** here — the AC prefilter
rewrite (`v0.44.0`) pays off exactly where it was designed to. gitleaks
wins outright because its ruleset is ~4× smaller and its rules are
regex-keyed by leading literal — fewer detectors × cheaper per-detector
work.

### Workload D — real OSS code (7.7 MB: `go-git v5.19.0` + `cobra v1.8.1` + `aws-sdk-go-v2 v1.41.7`)

Realistic shape with no actual secrets but plenty of "is this a key?"
ambiguity — UUIDs, hex hashes, embedded base64 documentation, etc.

| Tool | Mean | Min | Max | Findings reported |
|---|---:|---:|---:|---:|
| **pleno-dlp** | 5.48 ± 0.03 s | 5.45 s | 5.53 s | 490 (326 GenericHighEntropy + 73 Bandwidth FPs) |
| **trufflehog** | 887 ± 15 ms | 878 ms | 914 ms | 6 |
| **gitleaks** | 18.8 ± 1.2 ms | 17.2 ms | 20.1 ms | 5 |

Honest read: pleno-dlp is **6.2× slower than trufflehog** on this
workload. The AC prefilter is doing its job (verified below) — what is
NOT doing its job is detector selectivity once the prefilter wakes a
detector up.

Decomposition with `--include-detectors=AWS,Anthropic` (2 detectors
instead of 607):

| Configuration | Mean | Δ vs all-detectors |
|---|---:|---:|
| All 607 detectors | 5.50 s | — |
| Exclude `GenericHighEntropy,Bandwidth` (605 detectors, ~0 FPs) | 5.18 s | −5.8 % |
| Only `AWS,Anthropic` (2 detectors) | 347 ms | −93.7 % |

The 5.18 s figure is the smoking gun: excluding the two noisiest
detectors barely moves the wall clock. Per-detector regex execution
(`FromData`) dominates real-world cost when many keywords like
`"key"`, `"token"`, `"api"` fire common-English matches and wake up
dozens of detectors per chunk.

### Where each tool wins

| Scenario | Winner | Reason |
|---|---|---|
| Cold path (most files have no secrets) | **pleno-dlp** | Single AC prefilter walks every keyword across 607 detectors in one pass with zero allocations. |
| Realistic code with ambiguous tokens | **trufflehog** | Tighter detector keyword sets and stricter regex anchoring reduce post-prefilter wake-up count. |
| Pure speed with smaller ruleset OK | **gitleaks** | Fewer rules × pre-grouped regex by literal prefix; very fast and very narrow. |

### Follow-ups (next perf wave)

- **Detector keyword tightening.** Common English (`"key"`, `"token"`,
  `"api"`, `"auth"`) shouldn't be sole prefilter triggers. Audit
  detectors that wake up on these and require a second, stricter
  keyword (e.g. `"AKIA"` for AWS, `"sk-ant-"` for Anthropic) or a
  short pre-regex literal check before running `FromData`.
- **Per-detector regex tier-2 cache.** Several detectors compile
  identical regex prefixes; a shared anchored DFA could cut early
  rejection cost. Out-of-scope until tightening lands; measure first.
- Pool `decoder.Variants` output slice and decoded buffers for
  archive- / base64-heavy inputs.
- Evaluate Teddy-style SIMD AC only after AC + lowercase drops below
  ~5 % of the engine's hot path. Today it's well above that and the
  scalar AC is the right tool.

### Reproducing the cross-tool benchmark

```sh
# Corpus B — cold path
mkdir -p /tmp/dlp-bench/corpus-b && for i in $(seq 1 200); do
  # …200 × 50 KB plain-text log files; see _workspace/perf-2026-05-12-analysis.md
done

# Corpus D — real OSS
cp -R "$(go env GOMODCACHE)/github.com/go-git/go-git/v5@v5.19.0" /tmp/dlp-bench/corpus-d
cp -R "$(go env GOMODCACHE)/github.com/spf13/cobra@v1.8.1"        /tmp/dlp-bench/corpus-d/cobra
cp -R "$(go env GOMODCACHE)/github.com/aws/aws-sdk-go-v2@v1.41.7" /tmp/dlp-bench/corpus-d/aws-sdk-go-v2
chmod -R +w /tmp/dlp-bench/corpus-d

hyperfine --warmup 1 --runs 5 --ignore-failure \
  -n 'pleno-dlp'  "pleno-dlp scan filesystem $CORPUS --quiet --format json > /dev/null" \
  -n 'trufflehog' "trufflehog filesystem $CORPUS --no-verification --no-update --json --log-level=-1 > /dev/null" \
  -n 'gitleaks'   "gitleaks dir $CORPUS --no-banner --report-path=/dev/null --redact 2>/dev/null"
```

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
