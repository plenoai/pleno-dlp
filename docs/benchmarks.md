# Benchmarks

A snapshot of where pleno-dlp's engine sits today, measured against
`trufflehog` and `gitleaks` on the same hardware, the same corpora,
the same invocation pattern. Re-run the commands at the bottom to
refresh on your own box.

Captured 2026-05-12. Apple M3 · macOS 25.3 · go 1.25.2 · 607
detectors registered · `hyperfine 1.20.0`, 1 warmup + 5 runs.

| Tool        | Version | Detectors | Invocation                                                  |
|-------------|---------|----------:|-------------------------------------------------------------|
| pleno-dlp   | HEAD    |       607 | `scan filesystem $C --quiet --format json > /dev/null`      |
| trufflehog  | 3.95.2  |      ~800 | `filesystem $C --no-verification --no-update --json --log-level=-1 > /dev/null` |
| gitleaks    | 8.30.1  |      ~160 | `dir $C --no-banner --report-path=/dev/null --redact`       |

Verify is off across the board so we're measuring engine cost, not
the upstream API roundtrips. Each tool's exit code is `--ignore`d —
both pleno-dlp and gitleaks default to non-zero when findings exist;
that is policy, not failure.

## Workload B — cold path

200 plain-text log files, **9.4 MB total**, **zero secrets**. The
dominant shape on real codebases: most files contain no secrets, so
every detector pays the prefilter cost and nothing pays the regex
cost.

| Tool        | Mean         | Min      | Max      |
|-------------|-------------:|---------:|---------:|
| pleno-dlp   | **288 ± 6 ms** | 281 ms | 296 ms   |
| trufflehog  | 851 ± 12 ms  | 842 ms   | 872 ms   |
| gitleaks    | 18.8 ± 0.9 ms | 18.1 ms | 20.4 ms |

All three emit 0 findings. **pleno-dlp is 2.95× faster than
trufflehog** on the workload that dominates real-world scans —
matches the design of the engine's single Aho-Corasick prefilter,
which walks every keyword across 607 detectors in one allocation-free
pass. gitleaks wins outright because its ruleset is ~4× smaller and
its rules are regex-keyed by leading literal: fewer detectors ×
cheaper per-detector work.

## Workload D — real OSS code

`go-git v5.19.0` + `cobra v1.8.1` + `aws-sdk-go-v2 v1.41.7`, **7.7 MB
total**. No real secrets but plenty of "is this a key?" ambiguity —
UUIDs, hex hashes, embedded base64 documentation.

| Tool        | Mean          | Min     | Max     | Findings |
|-------------|--------------:|--------:|--------:|---------:|
| pleno-dlp   | 5.48 ± 0.03 s | 5.45 s  | 5.53 s  | 490 (326 GenericHighEntropy + 73 Bandwidth FPs) |
| trufflehog  | 887 ± 15 ms   | 878 ms  | 914 ms  | 6        |
| gitleaks    | 18.8 ± 1.2 ms | 17.2 ms | 20.1 ms | 5        |

Honest read: **pleno-dlp is 6.2× slower than trufflehog** here. The
prefilter is doing its job; what is _not_ doing its job is detector
selectivity once the prefilter wakes a detector up.

Smoking-gun decomposition on the same corpus, same hyperfine run:

| Configuration                                                | Mean    | Δ vs all |
|--------------------------------------------------------------|--------:|---------:|
| All 607 detectors                                            | 5.50 s  | —        |
| Exclude `GenericHighEntropy,Bandwidth` (605 detectors)       | 5.18 s  | −5.8 %   |
| `--include-detectors=AWS,Anthropic` only                     | 347 ms  | **−93.7 %** |

Dropping the two noisiest detectors barely moves the wall clock —
the per-detector `FromData` regex execution dominates. Common
English keywords (`"key"`, `"token"`, `"api"`, `"auth"`) wake up
dozens of detectors per chunk on real source code. That's the next
optimisation surface; the prefilter pass is no longer the
bottleneck.

## Where each tool wins

| Scenario                              | Winner       | Why                                                                                       |
|---------------------------------------|--------------|-------------------------------------------------------------------------------------------|
| Cold path (most files no secrets)     | pleno-dlp    | Single AC prefilter walks every keyword across 607 detectors in one allocation-free pass. |
| Ambiguous tokens in real source       | trufflehog   | Tighter detector keyword sets + stricter regex anchoring reduce post-prefilter wake-ups.  |
| Pure speed with smaller ruleset OK    | gitleaks     | Fewer rules × pre-grouped regex by leading literal; very fast, very narrow.               |

## Microbenchmarks

Drive the engine directly via Go's `testing.B`. Same machine.

```text
goos: darwin   goarch: arm64   cpu: Apple M3
pkg: github.com/plenoai/pleno-dlp/pkg/engine

BenchmarkScan_ColdPath/conc=1-8         5    600904975 ns/op    6.98 MB/s    11.5 MB/op   13.4k allocs/op
BenchmarkScan_ColdPath/conc=4-8        22    168120714 ns/op   24.95 MB/s    11.9 MB/op   13.7k allocs/op
BenchmarkScan_ColdPath/conc=8-8        27    127376537 ns/op   32.93 MB/s    11.9 MB/op   13.8k allocs/op
BenchmarkScan_ColdPath/conc=16-8       27    132910412 ns/op   31.56 MB/s    11.9 MB/op   13.7k allocs/op
BenchmarkKeywordMatch-8              7772       424056 ns/op   45.28 MB/s        0 B/op       0 allocs/op
```

- `BenchmarkScan_ColdPath` — 1024 × 4 KiB chunks of noise routed
  through the full engine across worker counts. Throughput peaks at
  `conc=8` on this 8-core M3.
- `BenchmarkKeywordMatch` — the prefilter in isolation. Zero
  allocations per call once warm: the lowercase buffer and the
  "seen" bitmap both come out of `sync.Pool`s.

## Engine shape today

- **`pkg/ahocorasick`** — in-repo case-sensitive AC matcher (~200
  LOC, zero new module deps). Built once at engine construction over
  the lower-cased union of every detector's `Keywords()`.
- **`pkg/engine`** — `scanChunkLeaf` lower-cases each chunk variant
  once into a pooled buffer, walks AC, dispatches only the detectors
  a keyword unlocked. The `Verifier` interface assertion is resolved
  at construction time and cached on the engine.
- **Variants** — every chunk also goes through `decoder.Variants`
  (base64 / hex / percent), so a secret hidden inside `Authorization:
  Bearer <base64-of-token>` reaches the same detector path as a
  plain-text leak.

## Next optimisation surface

- **Detector keyword tightening.** Common English (`"key"`,
  `"token"`, `"api"`, `"auth"`) shouldn't be a sole prefilter
  trigger. Either pair with a second stricter keyword (e.g. `"AKIA"`
  for AWS, `"sk-ant-"` for Anthropic) or add a short pre-regex
  literal check before running `FromData`.
- **Per-detector regex tier-2 cache.** Several detectors compile
  near-identical regex prefixes; a shared anchored DFA could cut
  early-rejection cost. Defer until keyword tightening lands.
- **Pool `decoder.Variants` output.** Cheap win for archive- /
  base64-heavy inputs; measure first.
- **Teddy-style SIMD AC.** Only worth it once AC + lowercase drops
  below ~5 % of the engine's hot path. Today it's well above and the
  scalar AC is the right tool.

## Reproducing

```sh
# Corpus B — cold path (9.4 MB plain-text logs, 0 secrets)
mkdir -p /tmp/dlp-bench/corpus-b
for i in $(seq 1 200); do
  cat > "/tmp/dlp-bench/corpus-b/log_${i}.txt" <<'EOF'
2026-05-12T10:00:00Z INFO request=GET /healthz status=200 latency_ms=1.2
2026-05-12T10:00:01Z INFO request=GET /api/v1/users status=200 latency_ms=12.4
2026-05-12T10:00:02Z WARN slow query=select * from orders took=812ms
EOF
  for _ in $(seq 1 60); do
    cat "/tmp/dlp-bench/corpus-b/log_${i}.txt" >> "/tmp/dlp-bench/corpus-b/log_${i}.txt.tmp"
  done
  mv "/tmp/dlp-bench/corpus-b/log_${i}.txt.tmp" "/tmp/dlp-bench/corpus-b/log_${i}.txt"
done

# Corpus D — real OSS
cp -R "$(go env GOMODCACHE)/github.com/go-git/go-git/v5@v5.19.0" /tmp/dlp-bench/corpus-d
cp -R "$(go env GOMODCACHE)/github.com/spf13/cobra@v1.8.1"        /tmp/dlp-bench/corpus-d/cobra
cp -R "$(go env GOMODCACHE)/github.com/aws/aws-sdk-go-v2@v1.41.7" /tmp/dlp-bench/corpus-d/aws-sdk-go-v2
chmod -R +w /tmp/dlp-bench/corpus-d

# Wall-clock comparison
CORPUS=/tmp/dlp-bench/corpus-b  # or corpus-d
hyperfine --warmup 1 --runs 5 --ignore-failure \
  -n pleno-dlp  "pleno-dlp scan filesystem $CORPUS --quiet --format json > /dev/null" \
  -n trufflehog "trufflehog filesystem $CORPUS --no-verification --no-update --json --log-level=-1 > /dev/null" \
  -n gitleaks   "gitleaks dir $CORPUS --no-banner --report-path=/dev/null --redact 2>/dev/null"

# Microbenchmarks
go test -bench=. -benchmem -benchtime=3s -run=Bench ./pkg/engine
```
