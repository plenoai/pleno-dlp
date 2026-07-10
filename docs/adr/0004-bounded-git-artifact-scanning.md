# ADR 0004: Bounded Git archive and binary history scanning

Status: accepted

## Context

Git history currently drops binary blobs before they reach the engine. This
also drops ZIP, TAR, gzip, and bzip2 archives. Scanning them without budgets
would expose org-wide history scans to compressed bombs, large generated
artifacts, excessive allocations, and unpredictable wall time.

## Decision

Both surfaces are opt-in and independent:

- `--include-git-archives` expands recognized archives and scans leaf entries.
- `--include-git-binaries` scans otherwise-binary blob bytes. It does not
  implicitly enable archive expansion.

Defaults and hard per-blob budgets are:

| Budget | Default |
| --- | ---: |
| compressed/raw blob bytes | 10 MiB |
| one expanded entry | 10 MiB |
| total expanded bytes | 50 MiB |
| expanded files | 1,000 |
| recursion depth | 3 |
| expansion timeout | 5 seconds |

Blob reads use a capped reader. Archive readers enforce every budget while
walking, check cancellation between headers and reads, and return a visible
degraded-scan error on a breached budget; partial expansion is not treated as
complete. Archive leaf and raw-binary chunks use the same 1 MiB chunk bound
and 512-byte detector-boundary overlap as large Git text changes.

Absolute paths, parent-traversal paths, and every ZIP/TAR symlink or hard-link
entry are rejected. Each rejection, corrupt entry, timeout, or budget breach
is returned as typed partial degradation while successfully extracted siblings
remain scannable. Artifact work reserves from a process-wide 200 MiB weighted
budget, backpressuring concurrent repository workers.

Archive and binary modifications scan the new blob once per touching commit;
they do not attempt a binary diff. Metadata paths use `outer!inner` for archive
entries and retain commit SHA, author, and date.

## Consequences

Default Git/GitHub behavior and cost remain unchanged. Opt-in archive scans
may add CPU and allocations but are bounded per changed blob. Findings beyond
a configured budget are intentionally unavailable and the scan reports why,
rather than silently claiming complete coverage. Arbitrary binary scanning is
expected to be noisier and remains a separate opt-in.

Before considering either surface default-on, benchmark a representative
large repository and record wall time, peak RSS, clone bytes, expanded bytes,
files, and findings.
