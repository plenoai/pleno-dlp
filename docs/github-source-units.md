# GitHub source-unit lifecycle

GitHub scan surfaces share a bounded lifecycle. A unit is identified by
`<surface>:<stable-id>`. Producers report each unit's observed cost in items
and bytes after it completes. Producers run concurrently; their results are
committed in discovery order so incremental state and partial flushes are
deterministic even when units finish out of order. A unit failure carries
forward its last valid state and does not stop unrelated units.

Repository history uses `repository-history:<owner>/<repo>`. Its clone and walk
pool is controlled by `scan github --repo-concurrency` (default 1, maximum 32),
independently from detector `--concurrency`.

The remaining GitHub surfaces plug into the same contract:

- #325: repository-wiki units.
- #320: bounded archive/binary work inside repository-history units.
- #323: collaboration scans (issues, pull requests, comments) run inside their
  repository's repository-history unit; failures are attributed per API surface
  (`repository-issues:<owner>/<repo>`, `repository-pull-requests:<owner>/<repo>`,
  `repository-comments:<owner>/<repo>`) and per-surface cursors are stored
  inside the repository's state entry.
- #319: gist-history and gist-comments units keyed by stable gist ID.

Common completion statistics include completed and failed units, skipped-reason
counts, producer cost in items/bytes, and peak pending results.

JSON and SARIF are byte-identical across scheduler completion orders while
buffered chunks remain bounded by the active concurrency window.

Incremental state version 3 records stable repository IDs, scope fingerprints,
last-seen/unobserved metadata, complete-run counts, and tombstones. Renames
restore state by stable ID. An unobserved entry is pruned only after both
`--state-retention-days` and `--state-retention-runs` thresholds are met;
scope changes and partial/degraded enumerations do not trigger pruning. V1 repo
maps and V2 surface maps migrate without dropping wiki, gist, or collaboration
namespaces.

REST pagination is constrained to the configured API scheme, origin, and path
base before authentication is read or attached. Pull-request collaboration
pages stop after a wholly out-of-window page only while descending `updated_at`
ordering remains intact; mixed ordering disables the optimization.

Repository workers within one scan client share adaptive rate coordination.
Healthy quota remains fully concurrent; remaining quota at or below 10
serializes new requests, remaining quota above 50 restores concurrency, and
exhausted/reset windows remain cancellation-aware.
