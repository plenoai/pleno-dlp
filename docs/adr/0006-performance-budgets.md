# ADR-0006: Preserve detection while bounding scanner overhead

Status: accepted

## Context

Reproducible filesystem probes exposed five separate costs: scanning sparse
text, rejecting dense keyword candidates, reading binary assets, retaining
expanded archive entries, and allocating decoded-input intermediates. Existing
benchmarks covered recall and Git history but did not gate these subsystems.

## Decision

Keep the existing detector registry and standard-library regular expressions.
Compile the keyword trie into a compact byte DFA; reuse hit buffers and merge
ordered vicinity spans while collecting them. Reject impossible candidates
using necessary syntax only, leaving the original detector grammar in charge.
Sniff binary inputs before reading their bodies, preallocate known file sizes,
and visit validated archive leaves through the existing streaming API.
Archive extraction retains its cumulative time budget, excluding detection and
remote verification time. Window Base64 decoding borrows a pooled buffer;
result bytes are detached before emission. The existing decoder API retains
owned outputs.

`make bench-performance` measures five fixed workloads against checksum-pinned
Gitleaks and TruffleHog. Each primary median must be at most 1.20 times the
better competitor. Every scan must find every unique canary; when a baseline
binary is supplied, all pleno-dlp finding signatures must remain identical.
Metrics are selected before tuning. Both wall time and RSS remain available in
the raw report even when only one is the task's primary gate.

## Consequences

The DFA spends bounded construction memory to avoid hash lookups per byte.
Hit buffers are reused across windows; dense keyword input still requires work
proportional to its matches. Archive callbacks release each scanned entry
instead of retaining the archive's complete expanded body. Correctness, race,
CLI and detector-unit checks remain release gates. Machine-sensitive performance
thresholds run separately on scheduled/manual CI, with raw artifacts retained.
These controlled synthetic workloads do not establish general recall parity
between different detector catalogs or performance on every repository.
