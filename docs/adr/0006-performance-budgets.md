# ADR-0006: Preserve detection while bounding scanner overhead

Status: accepted

## Context

Reproducible filesystem probes exposed five separate costs: scanning sparse
text, rejecting dense keyword candidates, reading binary assets, retaining
expanded archive entries, and allocating decoded-input intermediates. Existing
benchmarks covered recall and Git history but did not gate these subsystems.

## Decision

Keep the existing detector registry and standard-library regular expressions.
Initialize detector regexes with `sync.OnceValue` on first use, so keyword
dispatch does not require compiling unrelated providers at process startup.
Compile the keyword trie into a compact byte DFA; visit hits in input order
and merge vicinity spans without retaining every occurrence. Reject impossible candidates
using necessary syntax only, leaving the original detector grammar in charge.
Sniff binary inputs before reading their bodies, preallocate known file sizes,
and visit validated archive leaves through the existing streaming API.
Archive extraction retains its cumulative time budget, excluding detection and
remote verification time. Decode each chunk once before windowing so Base64
phase and hex-byte alignment cannot reset at an arbitrary window boundary.
Decoded outputs remain owned for the complete detector pass.

`make bench-performance` measures the input-shape matrix in
`bench/performance/run.py` against checksum-pinned Gitleaks, TruffleHog, and
Betterleaks. Both wall-time and peak-RSS medians must be at most 1.20 times the
best competitor for that metric. Every scan must find every unique canary; when a baseline
binary is supplied, all pleno-dlp finding signatures must remain identical.
Missing coverage, invalid output, timeouts, or incomplete samples invalidate
acceptance even when the measured cost is low. The earlier five-workload,
single-metric gate did not establish this contract.

## Consequences

The DFA spends bounded construction memory to avoid hash lookups per byte.
Dense keyword input still requires work proportional to its matches, without
retaining a hit-sized allocation. Archive callbacks release each scanned entry
instead of retaining the archive's complete expanded body. Correctness, race,
CLI and detector-unit checks remain release gates. Machine-sensitive performance
thresholds run separately on scheduled/manual CI, with raw artifacts retained.
These controlled synthetic workloads do not establish general recall parity
between different detector catalogs or performance on every repository.
