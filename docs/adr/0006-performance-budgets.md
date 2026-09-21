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
Compile the keyword trie into a byte DFA with no unused alphabet columns;
visit hits in input order and merge vicinity spans without retaining every
occurrence. Reject impossible candidates
using necessary syntax only, leaving the original detector grammar in charge.
Sniff binary inputs before reading their bodies. Files above 1 MiB expose
`Chunk.Open`, returning a replayable reader that the engine opens and closes
inside its worker. Consumers of `Source.Chunks` must handle this optional
payload; existing sources may continue supplying `Chunk.Data`.
Visit validated archive leaves through the existing streaming API. Archive
values above 1 MiB spill to temporary files; leaves above 128 KiB use readers
instead of allocating a second body-sized slice.
Archive extraction retains its cumulative time budget, excluding detection and
remote verification time. Decode complete runs or variants before windowing so
Base64 phase, hex-byte alignment, and printability decisions cannot reset at
an arbitrary window boundary. Large decoded variants use 0600 temporary files
removed after their synchronous detector pass, including error paths.

`ReaderDetector` lets whole-content secret detectors consume replayable inputs
without retaining unrelated bytes. External detectors without this optional
method retain their existing `FromData` semantics. Disabled PII detectors do
not read the input; enabled PII detectors still receive the complete variant.
Finding byte spans refer to the original input, even when detector windows
reuse their buffers. Resolve up to 1,024 pending findings in one source pass
and cache the first occurrence of each raw value, avoiding one full scan per
finding. Long raw values retain the existing search path. Source failures
remain visible when a decoder rejects a non-printable run. A read or close failure prevents the CLI from
advancing its durable incremental checkpoint.

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
instead of retaining the archive's complete expanded body. Whole-content
fallbacks, cached raw spans, and the actual secret bytes required by findings still consume memory
proportional to their input or output; this is not a universal constant-memory
guarantee. Correctness, race,
CLI and detector-unit checks remain release gates. Machine-sensitive performance
thresholds run separately on scheduled/manual CI, with raw artifacts retained.
These controlled synthetic workloads do not establish general recall parity
between different detector catalogs or performance on every repository.
