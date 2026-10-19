# Dogfooding pleno-dlp

Dogfooding only works if the operator machine runs a recent binary: the
CLI *is* the deliverable, and a stale build silently misses new
detectors, sources, and fixes.

## Decision

**Dogfood the released binary through the Homebrew tap. Do not pin
pleno-dlp with a mise `go:` entry.**

```sh
brew install plenoai/tap/pleno-dlp
```

`brew install` pulls the signed release binary from
[plenoai/homebrew-tap](https://github.com/plenoai/homebrew-tap). Every
tag release republishes `Casks/pleno-dlp.rb` in that tap, and only after
the GitHub Release is immutable, so there is exactly one version source.
Keep the machine current with:

```sh
brew upgrade pleno-dlp
```

The tap update is wired in `.goreleaser.yaml` (`homebrew_casks`) and the
`homebrew` job in `.github/workflows/release.yml`; see
[`output-and-gating.md`](output-and-gating.md#github-action) for the
artifact-signing story.

## Migrating an operator machine off the mise pin

```sh
# 1. Delete the go: entry from ~/.config/mise/config.toml.
# 2. Uninstall any cached source build.
mise uninstall go:github.com/plenoai/pleno-dlp/cmd/pleno-dlp 2>/dev/null || true
# 3. Switch to the released binary.
brew install plenoai/tap/pleno-dlp
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

Dropping it in favour of the Homebrew tap removes the second version
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
pleno-dlp is reintroduced into the tree, if the dogfooding doc stops
naming the tap, or if the release pipeline stops publishing the cask.
