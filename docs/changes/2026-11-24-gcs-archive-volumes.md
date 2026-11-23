Owners: connector-engineer, core-engineer, qa

The GCS source now matches S3: archive objects are emitted whole for engine expansion (50 MiB compressed budget, archive coverage gaps reported as `gcs-object-sha256:` locators), split volumes are grouped across listing pages and joined with `archive.JoinVolumes`, a set is checkpointed only when every volume was read, and per-object read or listing failures become `DegradedError` coverage gaps instead of being silently skipped. Volume grouping moved to the shared `pkg/sources/volumeset` package used by both S3 and GCS (#944).
