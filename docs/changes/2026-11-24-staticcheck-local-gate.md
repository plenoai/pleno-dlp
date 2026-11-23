Owners: architect, qa

`scripts/race-affected.sh` now also runs the pinned staticcheck
(2025.1.1) over the affected packages, matching the test.yml/release.yml
gate. v0.71.0 failed its `quality` job on ST1005 in
`pkg/detectors/catalog/signed.go` because delegates without a local
staticcheck install merged on race tests alone; the error strings are fixed.
