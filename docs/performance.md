# Five-subsystem performance comparison

Measured 2026-09-21 on Apple M3, macOS arm64, Go 1.26.8. Baseline source:
`d7ef52429f78b93837607cce3b445bdd7ec33cdc`. Competitors are the existing
checksum-pinned TruffleHog 3.96.0 and Gitleaks 8.30.1 releases.

## Technical investigation

[TruffleHog's AC core](https://github.com/trufflesecurity/trufflehog/blob/v3.96.0/pkg/engine/ahocorasick/ahocorasickcore.go)
uses keyword matches to select detectors and merge their scan ranges.
[Gitleaks' detector](https://github.com/gitleaks/gitleaks/blob/v8.30.1/detect/detect.go)
also prefilters rules before evaluating their regular expressions. Having an
Aho-Corasick matcher alone does not ensure competitive performance: pleno-dlp
still used a map lookup and failure walk for every byte, allocated every hit
list, then stored and sorted already ordered overlapping ranges.

[TruffleHog's filesystem source](https://github.com/trufflesecurity/trufflehog/blob/v3.96.0/pkg/sources/filesystem/filesystem.go)
and [Gitleaks' file processing](https://github.com/gitleaks/gitleaks/blob/v8.30.1/sources/file.go)
make input handling another independent comparison axis. pleno-dlp read complete
binary files before discarding them. Its engine called a collecting archive API
even though the repository already provided a streaming equivalent. Whole-file
and window decoding also produced repeated copies and temporary buffers.

The initial profiles identified these costs:

- Sparse logs: roughly 33% of sampled CPU in keyword matching and 43% in two
  whole-file structural regular expressions.
- Keyword-dense documentation: roughly 85% in regular expressions. Necessary
  syntax checks reject impossible candidates before the original grammar runs.
- Encoded input: a 27 MiB engine workload allocated roughly 646 MiB for keyword
  hits alone. Reusing hit storage removed that repeated allocation.
- Binary trees: allocating entire rejected assets multiplied memory by input
  concurrency.
- ZIP input: collecting all expanded entries retained the complete expanded
  body, plus decompression and detector buffers.

The implementation uses a compact byte DFA, reusable hit and decode buffers,
online range merging, necessary-syntax guards, prefix-first binary checks,
preallocated reads, and the existing archive streaming API. Decoded result
bytes are copied before their scratch buffer can be reused. Archive extraction
keeps its previous cumulative timeout, excluding detector/verification time.
No detectors or valid input forms were removed to meet the performance budgets.
See [ADR-0006](adr/0006-performance-budgets.md).

## Method

`make bench-performance` regenerates five deterministic workloads. The primary
metrics were selected before tuning: wall time for sparse text and dense
keyword rejection; peak RSS for binary rejection, archive expansion, and
Base64 normalization. The acceptance condition is
`pleno median / min(Gitleaks median, TruffleHog median) <= 1.20`.
A smaller ratio is better; outperforming a competitor is not a failure.

Each timed CLI invocation scans the same bytes and writes JSON to a captured
pipe. The parent validates every unique generated GitHub token and, with
`--baseline-bin`, compares the entire pleno-dlp finding signature including
source metadata. Missing canaries, unexpected GitHub results, changed baseline
results, scan errors, and timeouts fail the run. Only hashes and counts are
stored in the report. Each tool uses its complete default secret rule set,
verification disabled, PII off, one decoding layer, archive depth three, and
binary skipping. GOMAXPROCS is eight; pleno-dlp and TruffleHog have eight scan
workers. Gitleaks retains its own worker policy.

Two warmups precede seven measured runs per tool and workload. Starting order
rotates every round. Wall time includes process startup and output capture;
`/usr/bin/time` supplies peak RSS (Darwin bytes, Linux KiB converted to bytes).
The raw JSON records both metrics for every sample, tool versions and binary
SHA-256 hashes, corpus inventories and digests, CPU count and platform.

## Results

| Task / primary metric | Before | After | Gitleaks | TruffleHog | After / best |
|---|---:|---:|---:|---:|---:|
| Sparse text / structural matching (ms) | 750.88 | 160.40 | 365.39 | 1109.34 | 0.439× |
| Dense keyword candidate rejection (ms) | 3789.34 | 354.39 | 508.24 | 1141.29 | 0.697× |
| Binary input rejection (MiB) | 205.58 | 50.58 | 65.84 | 152.44 | 0.768× |
| ZIP expansion (MiB) | 145.22 | 82.97 | 74.67 | 265.61 | 1.111× |
| Base64 normalization (MiB) | 213.06 | 100.48 | 86.45 | 262.42 | 1.162× |

All five baselines exceeded the 1.20 budget (2.06×, 7.46×, 3.12×, 1.94×,
2.46× respectively). All five final medians pass. The largest remaining primary
gap is Base64 RSS at +16.23%. Every timed invocation passed canary validation,
and all candidate findings matched the baseline signatures.

Secondary metrics are not all within 20%: sparse text and dense keywords use
120.44 and 146.78 MiB RSS versus Gitleaks' 79.39 and 112.56 MiB. These tasks
were selected for CPU cost; the change reduces their own baseline RSS, but does
not establish memory parity for them. The three memory workloads also finish
faster than both competitors in this run.

The complete [raw samples](../bench/performance/results-2026-09-21.json) include
all seven observations, corpus digests and executable hashes.

## Regression validation

The full race suite, tagged detector suite, `go vet`, staticcheck, CLI E2E and
build are release gates. `govulncheck` reports no reachable vulnerabilities
(one module-only advisory remains outside the call graph).
The existing 48-file synthetic suite detects 47 files; its previously documented
Azure storage connection-string miss remains. Direct before/after CLI scans of
that corpus produce the same 57 findings and complete finding signature
`771fc46d461858120ff4696ade2de08c34cae2a5cac070130056d2fd5ca470c5`.

## Scope and reproduction

These synthetic workloads isolate five subsystems; they are not a claim of
universal superiority or equivalent detector catalogs. Canary parity is a
coverage guard, not a broad recall study. The existing synthetic recall suite,
detector tests and CLI tests remain necessary. Warm page caches, a single
machine, Go garbage-collection timing, and background desktop activity limit
cross-machine inference. Secondary metrics remain in the raw JSON even when
not the primary gate.

```sh
mkdir -p /tmp/pleno-before-src
git archive d7ef52429f78b93837607cce3b445bdd7ec33cdc | tar -x -C /tmp/pleno-before-src
(cd /tmp/pleno-before-src && go build -o /tmp/pleno-dlp-before ./cmd/pleno-dlp)
make bench-performance BENCH_PERFORMANCE_ARGS='--baseline-bin /tmp/pleno-dlp-before'
```

Results are written to
`bench/results/performance.json`; scheduled/manual CI retains that report as an
artifact and fails when any of the five budgets is exceeded.
