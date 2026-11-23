Owners: architect, qa

Dogfood pleno-dlp from the org-owned plenoai/aqua-registry as a `github_content` registry pinned by commit SHA (pin moved to v0.70.1); delete `aqua/registry.yaml` so that repository is the single source of truth, allow it in `aqua/aqua-policy.yaml` without `ref`, document the user-side config in README, and add `scripts/bump-dogfooding.sh` + `.github/workflows/dogfooding-bump.yml` (release-published and daily) to open pin/SHA/checksum bump PRs. No upstream aquaproj PRs (#931).
