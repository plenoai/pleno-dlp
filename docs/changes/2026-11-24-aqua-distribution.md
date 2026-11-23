Owners: architect, qa

Retire the Homebrew tap (its GitHub App was never created) and distribute release binaries through aqua only: drop the `homebrew` release job, `HOMEBREW_TAP_*` usage, and `homebrew_casks`; add `aqua/aqua.yaml` + `aqua/registry.yaml` (checksums.txt verified with its cosign bundle and the `release.yml` artifact attestation) as the dogfooding pin, mirror the registry entry to aquaproj/aqua-registry, and guard the asset contract and the absence of Homebrew in `tests/ci/dogfooding_test.go`.
