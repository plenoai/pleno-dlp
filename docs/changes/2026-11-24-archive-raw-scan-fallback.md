Owners: core-engineer, connector-engineer, qa

Every failed or partial archive expansion now also scans the outer container's raw bytes while keeping the coverage gap: the engine `Data`/`Open` paths, the go-git/native/offline git walkers (via `archive.WalkStreamWithRawFallback`, which replays the same spool), S3/GCS objects over the archive memory cap (streamed raw under the object limit), and archive files inside docker image layers (no longer dropped by the binary filter). `tests/e2e/06_unopenable_archive_raw_scan.sh` reports a key inside a lone `.z01` and a truncated zip (#970).
