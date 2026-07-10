#!/usr/bin/env bash
# Bumps a pinned competitor tool version (trufflehog | gitleaks) in both
# bench/scripts/fetch-tools.sh and bench/harness/tools.go together, in
# one diff — exactly the two files bench/CONTRIBUTING.md's "Bumping a
# pinned tool version" section requires to move in lockstep. Every
# platform's sha256 is read from that release's own *_checksums.txt
# asset (never hand-computed), matching the CONTRIBUTING.md-documented
# process. Used by .github/workflows/comparison-refresh.yml (issue
# #299) when it detects a new upstream release; safe to run locally.
#
# Usage: bench/scripts/bump-competitor-pin.sh <trufflehog|gitleaks> <version-without-v>
set -euo pipefail

tool="${1:?usage: bump-competitor-pin.sh <trufflehog|gitleaks> <version>}"
version="${2:?usage: bump-competitor-pin.sh <trufflehog|gitleaks> <version>}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fetch_tools="$repo_root/bench/scripts/fetch-tools.sh"
tools_go="$repo_root/bench/harness/tools.go"

case "$tool" in
  trufflehog) gh_repo="trufflesecurity/trufflehog" ;;
  gitleaks)   gh_repo="gitleaks/gitleaks" ;;
  *) echo "bump-competitor-pin: unknown tool '$tool' (want trufflehog|gitleaks)" >&2; exit 1 ;;
esac

checksums_url="https://github.com/${gh_repo}/releases/download/v${version}/${tool}_${version}_checksums.txt"
checksums_file="$(mktemp)"
trap 'rm -f "$checksums_file"' EXIT
echo "bump-competitor-pin: fetching $checksums_url"
curl -fsSL "$checksums_url" -o "$checksums_file"

sha_for() {
  local archive="$1" line
  line="$(grep -F " ${archive}" "$checksums_file" || true)"
  if [ -z "$line" ]; then
    echo "bump-competitor-pin: no checksum line for $archive in $checksums_url" >&2
    exit 1
  fi
  awk '{print $1}' <<<"$line"
}

# set_case_sha rewrites exactly the sha256 literal on the line
# `<key>) echo "<sha>" ;;` inside function <fn>'s body in
# fetch-tools.sh — scoped by function name so bumping one tool never
# touches the other tool's case statement, even though both functions
# share the same platform keys (darwin_arm64 etc).
set_case_sha() {
  local fn="$1" key="$2" sha="$3"
  awk -v fn="$fn" -v key="$key" -v sha="$sha" '
    $0 ~ "^" fn "\\(\\) \\{" { infn=1 }
    infn && index($0, key ")") > 0 {
      sub(/"[0-9a-f]+"/, "\"" sha "\"")
    }
    infn && /^}/ { infn = 0 }
    { print }
  ' "$fetch_tools" > "$fetch_tools.tmp"
  chmod +x "$fetch_tools.tmp"
  mv "$fetch_tools.tmp" "$fetch_tools"
}

case "$tool" in
  trufflehog)
    sed -i.bak -E "s/^TRUFFLEHOG_VERSION=\"[^\"]*\"/TRUFFLEHOG_VERSION=\"${version}\"/" "$fetch_tools"
    set_case_sha trufflehog_sha256 darwin_arm64 "$(sha_for "trufflehog_${version}_darwin_arm64.tar.gz")"
    set_case_sha trufflehog_sha256 darwin_amd64 "$(sha_for "trufflehog_${version}_darwin_amd64.tar.gz")"
    set_case_sha trufflehog_sha256 linux_arm64  "$(sha_for "trufflehog_${version}_linux_arm64.tar.gz")"
    set_case_sha trufflehog_sha256 linux_amd64  "$(sha_for "trufflehog_${version}_linux_amd64.tar.gz")"
    ;;
  gitleaks)
    sed -i.bak -E "s/^GITLEAKS_VERSION=\"[^\"]*\"/GITLEAKS_VERSION=\"${version}\"/" "$fetch_tools"
    # gitleaks names its amd64 tarball "x64" (see gitleaks_arch_name in
    # fetch-tools.sh) — the case *key* stays "darwin_amd64"/"linux_amd64"
    # (matched against uname -m, normalized), only the release asset
    # filename uses "x64".
    set_case_sha gitleaks_sha256 darwin_arm64 "$(sha_for "gitleaks_${version}_darwin_arm64.tar.gz")"
    set_case_sha gitleaks_sha256 darwin_amd64 "$(sha_for "gitleaks_${version}_darwin_x64.tar.gz")"
    set_case_sha gitleaks_sha256 linux_arm64  "$(sha_for "gitleaks_${version}_linux_arm64.tar.gz")"
    set_case_sha gitleaks_sha256 linux_amd64  "$(sha_for "gitleaks_${version}_linux_x64.tar.gz")"
    ;;
esac
rm -f "$fetch_tools.bak"

sed -i.bak -E "s/\"${tool}\":([[:space:]]*)\"[^\"]*\"/\"${tool}\":\1\"${version}\"/" "$tools_go"
rm -f "$tools_go.bak"

echo "bump-competitor-pin: ${tool} pinned version -> ${version} (fetch-tools.sh + tools.go updated)"
