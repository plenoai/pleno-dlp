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
| pleno-dlp   | **184 ± 10 ms** | 176 ms  | 201 ms   |
| trufflehog  | 872 ± 21 ms  | 858 ms   | 910 ms   |
| gitleaks    | 19.2 ± 0.6 ms | 18.4 ms | 19.7 ms |

All three emit 0 findings. **pleno-dlp is 4.73× faster than
trufflehog** on the workload that dominates real-world scans.
gitleaks still wins outright because its ruleset is ~4× smaller and
its rules are regex-keyed by leading literal; pleno-dlp closes most
of the gap to gitleaks while keeping ~4× the detector coverage.

## Workload D — real OSS code

`go-git v5.19.0` + `cobra v1.8.1` + `aws-sdk-go-v2 v1.41.7`, **7.7 MB
total**. No real secrets but plenty of "is this a key?" ambiguity —
UUIDs, hex hashes, embedded base64 documentation.

| Tool        | Mean          | Min     | Max     | Findings |
|-------------|--------------:|--------:|--------:|---------:|
| pleno-dlp   | **770 ± 115 ms** | 694 ms | 973 ms | 490 (326 GenericHighEntropy + 73 Bandwidth FPs) |
| trufflehog  | 1020 ± 105 ms | 944 ms  | 1198 ms | 6        |
| gitleaks    | 16.8 ± 0.8 ms | 16.1 ms | 17.8 ms | 5        |

**pleno-dlp is 1.32× faster than trufflehog** here too — a reversal
from the previous snapshot, where pleno-dlp was 6.2× slower on the
same corpus. Finding counts are identical to the pre-optimisation
baseline; detection parity was an explicit constraint on the rework.
The flip came from three coordinated engine changes:

1. **decoder.Variants byte-scan gating + RE2 removal.** The
   base64 / hex / percent run detectors used to walk every chunk
   through RE2 even when no candidate run existed. Profiling showed
   the cold-path engine spending ~26% of CPU inside
   `regexp.(*machine).match` rooted in `decoder.Variants`. A linear
   scan rejects "no candidate" in one pass; the regex was also
   replaced by a `walkBase64Runs` / `walkHexRuns` byte walker so the
   match path itself never enters RE2.
2. **Generic-detector pre-check.** `GenericHighEntropy`'s
   `secretShape` regex (`[A-Za-z0-9+/_\-]{20,128}`) was running once
   per chunk that mentioned any of its credential keywords, even on
   plain English prose with no token-shaped substring at all. A
   cheap byte-scan gate skips the regex entirely when the chunk has
   no run of >=20 base64-alphabet bytes.
3. **Vicinity dispatch.** The biggest single win on real source code.
   The dispatcher now collects every AC keyword hit's exact position
   and hands each detector only the union of `keyword_position ±
   2 KiB` byte ranges — instead of the full 32 KiB window. Detector
   regexes scale linearly in input size, so capping per-dispatch
   work at the radius the credential regexes are written against
   (~256-byte keyword-secret gap, plenty of headroom) cuts the
   per-detector cost from O(window_size) to O(num_hits ·
   2·vicinityRadius). On a Go codebase with locally-clustered
   credential keywords, that's a flat ~3× reduction in detector
   regex time.

Detection-parity rescue: the first iteration of vicinity dispatch
silently regressed five detector classes whose regexes legitimately
span > 2 KiB or pair literals across the same chunk — PrivateKeyPEM
(BEGIN/END across a multi-KiB body), APNs and AppStoreConnect (PEM
.p8 keys with a wider context keyword), GCP (extractObject walks
left/right for the enclosing JSON object), and Bandwidth (paired
secrets near the same keyword). They opt out of vicinity dispatch
via the new `detectors.FullChunkDetector` interface and receive the
whole chunk once before the windowing loop runs. Regression tests
in `pkg/engine/regression_test.go` lock the contract — running
them on the no-FullChunkDetector revision reproduces the misses.

The cost is per-chunk: five extra full-chunk regex sweeps regardless
of file content. That's what dragged Workload B from 102 ms (no
detection parity) to 184 ms (full detection parity). Detection
correctness was the right side of the trade — there is no point in
a faster DLP scanner that fails to find leaked private keys.

## Where each tool wins

| Scenario                              | Winner       | Why                                                                                       |
|---------------------------------------|--------------|-------------------------------------------------------------------------------------------|
| Cold path (most files no secrets)     | pleno-dlp    | Single AC prefilter + byte-scan decoder gates leave the cold path one linear pass.        |
| Ambiguous tokens in real source       | pleno-dlp    | Vicinity dispatch caps per-detector regex work at the radius the regex was written for.   |
| Pure speed with smaller ruleset OK    | gitleaks     | Fewer rules × pre-grouped regex by leading literal; very fast, very narrow.               |

## Microbenchmarks

Drive the engine directly via Go's `testing.B`. Same machine.

```text
goos: darwin   goarch: arm64   cpu: Apple M3
pkg: github.com/plenoai/pleno-dlp/pkg/engine

BenchmarkScan_ColdPath/conc=1-8        31    103110200 ns/op   40.68 MB/s   8.6 MB/op   18.4k allocs/op
BenchmarkScan_ColdPath/conc=4-8       130     28347204 ns/op  147.96 MB/s   8.6 MB/op   18.5k allocs/op
BenchmarkScan_ColdPath/conc=8-8       178     20491485 ns/op  204.69 MB/s   8.6 MB/op   18.5k allocs/op
BenchmarkScan_ColdPath/conc=16-8      165     21111344 ns/op  198.68 MB/s   8.6 MB/op   18.5k allocs/op
BenchmarkKeywordMatch-8              7196       423709 ns/op   45.31 MB/s     0 B/op        0 allocs/op
```

- `BenchmarkScan_ColdPath` — 1024 × 4 KiB chunks of noise routed
  through the full engine across worker counts. Throughput peaks at
  `conc=8` on this 8-core M3 — **205 MB/s, a 6.2× lift from the
  pre-optimisation 32.93 MB/s baseline** at the same concurrency.
- `BenchmarkKeywordMatch` — the prefilter in isolation. Zero
  allocations per call once warm: the lowercase buffer and the
  "seen" bitmap both come out of `sync.Pool`s.

A separate `BenchmarkScan_RealCorpus` benchmark (build-tagged
`realcorpus`, points at `/tmp/dlp-bench/corpus-d`) reproduces the
Workload D walltime under `go test`:

```text
BenchmarkScan_RealCorpus-8   3   577010306 ns/op   11.00 MB/s
```

Run it with:

```sh
go test -tags=realcorpus -run=^$ \
    -bench=BenchmarkScan_RealCorpus -benchtime=3x \
    -cpuprofile=/tmp/dlp.prof ./pkg/engine
```

## Engine shape today

- **`pkg/ahocorasick`** — in-repo case-sensitive AC matcher (~250
  LOC, zero new module deps). Built once at engine construction over
  the lower-cased union of every detector's `Keywords()`. Exposes
  `MatchHitsInto` for position-aware dispatch.
- **`pkg/engine`** — `scanChunkLeaf` slides a 32 KiB window (with
  1 KiB overlap) across each chunk. Per-window, `dispatch`
  lower-cases once into a pooled buffer, walks AC to collect
  `(detector_index, keyword_position)` hits, then runs each
  dispatched detector against the *minimal vicinity slice* covering
  every hit + `vicinityRadius` bytes on each side. The `Verifier`
  interface assertion is resolved at construction time and cached on
  the engine.
- **`pkg/decoder`** — `Variants` gates base64 / hex / percent decode
  on cheap byte scans (`hasBase64Run` / `hasHexRun` /
  `hasPercentRun`); run detection itself uses `walkBase64Runs` /
  `walkHexRuns` instead of RE2 so the no-decode path stays
  allocation-free.

## Next optimisation surface

- **Per-detector literal prefilter metadata.** Some detector regexes
  carry a hard literal (`hvs.` for Vault, `eyJ` for JWT) that's
  stronger than the registered keyword. Letting detectors declare it
  via an optional interface, and gating FromData on
  `bytes.Contains(slice, literal)`, would skip the regex on every
  vicinity that has the weaker keyword but no strong literal.
- **Per-detector regex tier-2 cache.** Several detectors compile
  near-identical regex prefixes; a shared anchored DFA could cut
  early-rejection cost. Defer until literal prefilter lands.
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
