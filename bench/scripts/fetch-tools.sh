#!/usr/bin/env bash
# Downloads the pinned trufflehog + gitleaks releases (versions defined
# once in bench/harness/tools.go's pinnedVersion, mirrored here since
# shell can't import Go) into bench/.tools/, verifying each archive's
# sha256 before extracting. This is the reproduction path for anyone
# (including CI) without a local trufflehog/gitleaks install — see
# bench/README.md and issue #298's "pinned 3-tool re-run" requirement.
#
# Written against bash 3.2 (macOS's shipped default, no `declare -A`) —
# case statements instead of associative arrays — since this needs to
# run unmodified on a stock macOS dev machine, not just CI's Linux
# runners.
#
# Usage: bench/scripts/fetch-tools.sh
set -euo pipefail

TRUFFLEHOG_VERSION="3.97.0"
GITLEAKS_VERSION="8.30.1"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) echo "fetch-tools: unsupported arch $arch" >&2; exit 1 ;;
esac
case "$os" in
  darwin|linux) ;;
  *) echo "fetch-tools: unsupported OS $os — install trufflehog/gitleaks manually and point -trufflehog-bin/-gitleaks-bin at them" >&2; exit 1 ;;
esac

# sha256 of each release's platform tarball, copied from the upstream
# release's own *_checksums.txt (trufflesecurity/trufflehog and
# gitleaks/gitleaks GitHub Releases for the versions pinned above).
# Bumping a pinned version requires updating both the version and every
# checksum below in the same diff — see bench/CONTRIBUTING.md.
trufflehog_sha256() {
  case "${os}_${arch}" in
    darwin_arm64) echo "ad0a99bd48d6df80eabab24d11d0fd771e245fc55ed347f943cafb5e5f497c5c" ;;
    darwin_amd64) echo "037e4aeb197870555ff515432bb5f1f2c98dce5f1214631a689112b5e0e4c9fd" ;;
    linux_arm64) echo "f48f57e3d4343377865b1b64653f96d381d61a7792d89d026e85524732039fde" ;;
    linux_amd64) echo "62224de2f9dd7cd418800feb953760a302ed2f82a7c547fe1146a4874fb179e4" ;;
    *) return 1 ;;
  esac
}
gitleaks_sha256() {
  case "${os}_${arch}" in
    darwin_arm64) echo "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5" ;;
    darwin_amd64) echo "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709" ;;
    linux_arm64) echo "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080" ;;
    linux_amd64) echo "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" ;;
    *) return 1 ;;
  esac
}
# gitleaks names its amd64 darwin/linux asset "x64", trufflehog names it
# "amd64" — normalize our lookup, not upstream's inconsistent naming.
gitleaks_arch_name() {
  case "$arch" in
    amd64) echo "x64" ;;
    arm64) echo "arm64" ;;
  esac
}

out_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.tools"
mkdir -p "$out_dir"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fetch_verify() {
  local url="$1" sha256="$2" archive="$3"
  echo "fetch-tools: downloading $url"
  curl -fsSL "$url" -o "$work/$archive"
  local got
  got="$(shasum -a 256 "$work/$archive" | awk '{print $1}')"
  if [ "$got" != "$sha256" ]; then
    echo "fetch-tools: checksum mismatch for $archive: got $got, want $sha256" >&2
    exit 1
  fi
}

# trufflehog
th_sha="$(trufflehog_sha256)" || { echo "fetch-tools: no pinned trufflehog checksum for ${os}_${arch} — add one (see this script's header)" >&2; exit 1; }
th_archive="trufflehog_${TRUFFLEHOG_VERSION}_${os}_${arch}.tar.gz"
fetch_verify "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/${th_archive}" "$th_sha" "$th_archive"
tar -xzf "$work/$th_archive" -C "$work" trufflehog
mv "$work/trufflehog" "$out_dir/trufflehog"
chmod +x "$out_dir/trufflehog"

# gitleaks
gl_arch="$(gitleaks_arch_name)"
gl_sha="$(gitleaks_sha256)" || { echo "fetch-tools: no pinned gitleaks checksum for ${os}_${arch} — add one (see this script's header)" >&2; exit 1; }
gl_archive="gitleaks_${GITLEAKS_VERSION}_${os}_${gl_arch}.tar.gz"
fetch_verify "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${gl_archive}" "$gl_sha" "$gl_archive"
tar -xzf "$work/$gl_archive" -C "$work" gitleaks
mv "$work/gitleaks" "$out_dir/gitleaks"
chmod +x "$out_dir/gitleaks"

echo "fetch-tools: installed trufflehog $TRUFFLEHOG_VERSION and gitleaks $GITLEAKS_VERSION to $out_dir"
