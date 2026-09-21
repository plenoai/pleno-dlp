#!/usr/bin/env bash
# Downloads the pinned trufflehog + gitleaks + betterleaks releases (versions defined
# once in bench/harness/tools.go's pinnedVersion, mirrored here since
# shell can't import Go) into bench/.tools/, verifying each archive's
# sha256 before extracting. This is the reproduction path for anyone
# (including CI) without a local competitor install — see
# bench/README.md and the pinned competitor re-run requirement.
#
# Written against bash 3.2 (macOS's shipped default, no `declare -A`) —
# case statements instead of associative arrays — since this needs to
# run unmodified on a stock macOS dev machine, not just CI's Linux
# runners.
#
# Usage: bench/scripts/fetch-tools.sh
set -euo pipefail

TRUFFLEHOG_VERSION="3.97.5"
GITLEAKS_VERSION="8.30.1"
BETTERLEAKS_VERSION="1.8.1"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) echo "fetch-tools: unsupported arch $arch" >&2; exit 1 ;;
esac
case "$os" in
  darwin|linux) ;;
  *) echo "fetch-tools: unsupported OS $os — install competitor binaries manually" >&2; exit 1 ;;
esac

# sha256 of each release's platform tarball, copied from the upstream
# release's checksum asset (trufflesecurity/trufflehog and gitleaks/gitleaks
# use *_checksums.txt; betterleaks/betterleaks uses checksums.txt) for the
# versions pinned above.
# Bumping a pinned version requires updating both the version and every
# checksum below in the same diff — see bench/CONTRIBUTING.md.
trufflehog_sha256() {
  case "${os}_${arch}" in
    darwin_arm64) echo "b4e5fd54aaea368342b226cbea228e7a33898b177598d1d8cd66edb14f87444e" ;;
    darwin_amd64) echo "cc8b12f8120fe47d7de929928e9183285b7a39eba60b3ac01f085f522ec19e50" ;;
    linux_arm64) echo "e5c8b2418b0a7c78cf4c47ac783c52c63f989e4e536cfe328b5271e819b6d52d" ;;
    linux_amd64) echo "e3d97199c565c37ca6152750197f667e08ae6a1edf5911fbdec168622b28620c" ;;
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
# gitleaks and betterleaks name their amd64 darwin/linux assets "x64",
# while trufflehog names them "amd64" — normalize our lookup, not
# upstream's inconsistent naming.
x64_arch_name() {
  case "$arch" in
    amd64) echo "x64" ;;
    arm64) echo "arm64" ;;
  esac
}
betterleaks_sha256() {
  case "${os}_${arch}" in
    darwin_arm64) echo "8e80f33b5f2a7426b390347b9fd466033723cb94b6bdffa7572632e2eaec964e" ;;
    darwin_amd64) echo "6abc37df76f881cffae406aa2cec72bea6e6ae64b4e771b3ed21b4aac472ed10" ;;
    linux_arm64) echo "bbb578b12a2f65d7082ab436abf37724232bc71d8a078e3c41336574420f1b48" ;;
    linux_amd64) echo "efa407244e1ea8e35f582b8a42becdeac08bdead04f68eb752adda722d583c2a" ;;
    *) return 1 ;;
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
gl_arch="$(x64_arch_name)"
gl_sha="$(gitleaks_sha256)" || { echo "fetch-tools: no pinned gitleaks checksum for ${os}_${arch} — add one (see this script's header)" >&2; exit 1; }
gl_archive="gitleaks_${GITLEAKS_VERSION}_${os}_${gl_arch}.tar.gz"
fetch_verify "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${gl_archive}" "$gl_sha" "$gl_archive"
tar -xzf "$work/$gl_archive" -C "$work" gitleaks
mv "$work/gitleaks" "$out_dir/gitleaks"
chmod +x "$out_dir/gitleaks"

# betterleaks
bl_arch="$(x64_arch_name)"
bl_sha="$(betterleaks_sha256)" || { echo "fetch-tools: no pinned betterleaks checksum for ${os}_${arch} — add one (see this script's header)" >&2; exit 1; }
bl_archive="betterleaks_${BETTERLEAKS_VERSION}_${os}_${bl_arch}.tar.gz"
fetch_verify "https://github.com/betterleaks/betterleaks/releases/download/v${BETTERLEAKS_VERSION}/${bl_archive}" "$bl_sha" "$bl_archive"
tar -xzf "$work/$bl_archive" -C "$work" betterleaks
mv "$work/betterleaks" "$out_dir/betterleaks"
chmod +x "$out_dir/betterleaks"

echo "fetch-tools: installed trufflehog $TRUFFLEHOG_VERSION, gitleaks $GITLEAKS_VERSION, and betterleaks $BETTERLEAKS_VERSION to $out_dir"
