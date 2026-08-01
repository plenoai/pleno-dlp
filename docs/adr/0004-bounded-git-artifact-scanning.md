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
| expanded leaf files | 1,000 |
| recursion depth | 3 |
| expansion timeout | 5 seconds |

The compressed/raw and total-expanded byte budgets are explicitly
configurable up to a 2 GiB hard ceiling. The conservative defaults remain
unchanged; exceeding any configured budget is degraded coverage, never a
successful complete scan.

The raw-input ceiling is passed explicitly to the archive reader; a caller
cannot turn an untrusted declared size into an uncapped spool. The go-git
filesystem store switches objects larger than 16 MiB to its lazy
reader. Raw blobs and expanded archive values are validated into a bounded
spool: at most 16 MiB stays in memory and larger values use `0600` temporary
files. Git consumes that spool one chunk at a time rather than constructing a
blob-sized byte slice or retaining all expanded leaves. Temporary files are
removed on success, rejection, corruption, timeout, cancellation, and callback
failure; a cleanup failure is itself visible degradation.

Archive readers enforce every budget while walking, check cancellation while
reading headers and bodies, and return a visible degraded-scan error on a
breached budget; partial expansion is not treated as complete. The expanded-
byte budget includes every successfully decoded intermediate archive as well
as leaf data. For example, a gzip-compressed TAR counts the decoded TAR bytes
and then each TAR member. Archive leaf and raw-binary chunks retain stable
archive order and use the same 1 MiB chunk bound and 512-byte detector-boundary
overlap as large Git text changes.

Absolute paths, parent-traversal paths, and every ZIP/TAR symlink or hard-link
entry are rejected. A ZIP's central-directory byte size and actual header count
are checked before `archive/zip` constructs its file table. Physical TAR
headers are likewise walked before `archive/tar` can interpret PAX/GNU
metadata. Archive headers have an independent 10,000 ceiling, ZIP central
directories a 16 MiB ceiling, and TAR PAX/GNU metadata a cumulative 1 MiB
ceiling; GNU sparse metadata is rejected. ZIP CRC and decompressor EOF are
validated before a leaf is emitted. Each rejection, corrupt entry, timeout, or
budget breach is returned as typed partial degradation while successfully
validated siblings remain scannable. Artifact work reserves atomically from a
process-wide 200 MiB weighted budget, backpressuring concurrent repository
workers without partial-acquisition deadlocks. Archive expansion takes the
full reservation and is therefore serialized process-wide. The reservation is
taken only after a changed blob is classified as an artifact, so enabling the
option does not serialize text-only commits. Binary-only work reserves two
copies of the actual blob size, clamped to the budget capacity.

Configured byte ceilings now bound work and temporary-disk use without making
heap proportional to a multi-GiB blob. Peak artifact-stage heap is instead
bounded by the 16 MiB spool threshold along the permitted nesting depth, the
go-git large-object threshold, ZIP metadata below its independent ceiling, and
one 1 MiB output window. A single 2 GiB blob can still require roughly its raw
size plus its permitted expanded intermediates in temporary disk space and can
consume substantial CPU until the timeout. The compatibility `archive.Walk`
API still accepts and returns byte slices and is not a bounded-memory API; Git
history uses the streaming API. Callers outside the normal engine pipeline
must also avoid retaining every emitted chunk indefinitely.

One compatibility tradeoff prevents a separate go-git allocation path:
content-similarity rename detection runs only when every add/delete candidate
is at most 1 MiB. With a larger candidate the walk still detects exact-hash
renames, while a modified large move is conservatively scanned as an addition
instead of being excluded as a rename.

Archive and binary modifications scan the new blob once per touching commit;
they do not attempt a binary diff. Metadata paths use `outer!inner` for archive
entries and retain commit SHA, author, and date.

## Consequences

Default Git/GitHub behavior and cost remain unchanged. Opt-in archive scans
may add substantial CPU and temporary-disk I/O even within their input/work
budgets. Findings beyond a configured budget are intentionally unavailable and
the scan reports why, rather than silently claiming complete coverage.
Arbitrary binary scanning is expected to be noisier and remains a separate
opt-in.

Before considering either surface default-on, benchmark a representative
large repository and record wall time, peak RSS, clone bytes, expanded bytes,
files, and findings.
