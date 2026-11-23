# Dogfooding pleno-dlp

Dogfooding only works if the operator machine runs a recent binary: the
CLI *is* the deliverable, and a stale build silently misses new
detectors, sources, and fixes.

## Decision

**Dogfood the released binary through aqua. Do not pin pleno-dlp with a
mise `go:` entry, and do not expect a Homebrew tap: there is none.**

```sh
aqua -c aqua/aqua.yaml i
aqua -c aqua/aqua.yaml exec -- pleno-dlp --help
```

`aqua/aqua.yaml` pins `plenoai/pleno-dlp@vX.Y.Z` from the GitHub Release
assets. Before installing, aqua checks the archive against
`checksums.txt`, verifies `checksums.txt` with its cosign keyless bundle
(`checksums.txt.sigstore.json`, identity
`plenoai/pleno-dlp/.github/workflows/release.yml@refs/tags/<version>`),
and verifies the archive's GitHub artifact attestation from the same
workflow. `aqua/aqua-checksums.json` records the expected digests.

The package definition lives only in
[plenoai/aqua-registry](https://github.com/plenoai/aqua-registry)
(`pkgs/plenoai/pleno-dlp/registry.yaml`, merged into `registry.yaml`).
`aqua/aqua.yaml` consumes it as a `github_content` registry pinned to a
commit SHA, so a registry change reaches operators only through a reviewed
pin bump. This repository keeps no copy: one source of truth. Nothing is
submitted to aquaproj/aqua-registry. `aqua/aqua-policy.yaml` allows the
registry without a `ref`, so SHA bumps need no policy change:

```sh
export AQUA_POLICY_CONFIG="$PWD/aqua/aqua-policy.yaml"
```

`.github/workflows/dogfooding-bump.yml` runs on every published release
and daily; it calls `scripts/bump-dogfooding.sh`, which moves the pin to
the newest release that ships `pleno-dlp_darwin_arm64.tar.gz`, moves
`ref` to the newest plenoai/aqua-registry `main` commit, refreshes the
checksums, and opens a pull request. To bump by hand:

```sh
scripts/bump-dogfooding.sh
```

The Homebrew tap was retired: it needed a GitHub App to write to a
second repository, which was never created. aqua reads the release
assets directly, so the release pipeline has no cross-repository write.

## Migrating an operator machine off the mise pin

```sh
# 1. Delete the go: entry from ~/.config/mise/config.toml.
# 2. Uninstall any cached source build.
mise uninstall go:github.com/plenoai/pleno-dlp/cmd/pleno-dlp 2>/dev/null || true
# 3. Switch to the released binary.
aqua -c aqua/aqua.yaml i
```

## Why the mise pin was dropped

The operator machine pinned pleno-dlp in
`~/.config/mise/config.toml` as
`go:github.com/plenoai/pleno-dlp/cmd/pleno-dlp`. That entry:

- compiled from source instead of consuming the released binary;
- lived in an unmanaged, machine-local file, so no dotfiles or
  Renovate-style automation could rewrite it; and
- silently drifted to **v0.46.0** while releases had reached **v0.66.x**
  — about 20 minors behind.

Dropping it in favour of the aqua pin removes the second version
source entirely.

## Rejected alternatives

- **Manage the `go:` pin from dotfiles (home-manager) with a
  Renovate-style bump.** Viable only if the dotfiles repository owns the
  file and automation regenerates the version. Our config was
  machine-local and unmanaged, so this was not possible without first
  centralising the file. It would also keep rebuilding from source
  rather than dogfooding the artifact operators actually ship.
- **`go install github.com/plenoai/pleno-dlp/cmd/pleno-dlp@latest`.**
  Fine for a one-off, but it is not pinned per project and does not
  exercise the signed release path.

## Guard

`tests/ci/dogfooding_test.go` fails the build if an ad-hoc mise pin for
pleno-dlp is reintroduced, if `aqua/aqua.yaml` stops pinning a released
version with checksums required, if it stops consuming the plenoai/aqua-registry
`github_content` registry pinned by a 40-hex commit SHA, if the policy
stops allowing that registry, if a local registry copy reappears, if the
bump workflow disappears, if GoReleaser renames the archives or the signed
checksum file the registry expects, or if Homebrew publication creeps back
into the release pipeline. The cosign and attestation requirements are
enforced by the registry entry itself and checked at install time.
