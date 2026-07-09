#!/usr/bin/env bash
# Polls trufflehog's and gitleaks's latest GitHub release and compares it
# against the version pinned in bench/scripts/fetch-tools.sh. Used by
# .github/workflows/comparison-refresh.yml's scheduled trigger (issue
# #299): a new upstream release the pin doesn't match yet is the signal
# to re-run `make bench`, bump the pin (bench/scripts/bump-competitor-pin.sh),
# and regenerate docs/comparison.md's live section.
#
# Authenticates with $GITHUB_TOKEN when set (raises the GitHub API rate
# limit for the two read-only "latest release" lookups below; the
# workflow's default token is enough, no new secret needed) but runs
# unauthenticated too for local use.
#
# Emits `key=value` lines to $GITHUB_OUTPUT if set (CI), and always to
# stdout (local use / debugging).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fetch_tools="$repo_root/bench/scripts/fetch-tools.sh"

pinned_version() {
  local var
  case "$1" in
    trufflehog) var="TRUFFLEHOG_VERSION" ;;
    gitleaks)   var="GITLEAKS_VERSION" ;;
  esac
  grep -E "^${var}=" "$fetch_tools" | head -1 | sed -E 's/^[A-Z_]+="([^"]*)"/\1/'
}

latest_release() {
  # $1 = owner/repo; prints the release's tag_name with any leading "v"
  # stripped. No array-based conditional flag building here (bash 3.2,
  # macOS's shipped default per fetch-tools.sh, raises "unbound
  # variable" under `set -u` when expanding an empty array) — a plain
  # if/else with two full curl invocations instead.
  local repo="$1" body
  # Buffer curl's output into a variable before piping into grep -m1:
  # piping curl directly into `grep -m1` lets grep close the pipe as
  # soon as it has its match, which can SIGPIPE curl mid-write — under
  # `set -o pipefail` that surfaces as the whole pipeline (and, via
  # `var=$(...)`, the enclosing `set -e` script) failing nondeterministically.
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    body="$(curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/${repo}/releases/latest")"
  else
    body="$(curl -fsSL -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/${repo}/releases/latest")"
  fi
  printf '%s\n' "$body" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"v?([^"]+)".*/\1/'
}

emit() {
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "$1=$2" >> "$GITHUB_OUTPUT"
  fi
  echo "$1=$2"
}

any_drift=false
for tool in trufflehog gitleaks; do
  case "$tool" in
    trufflehog) repo="trufflesecurity/trufflehog" ;;
    gitleaks)   repo="gitleaks/gitleaks" ;;
  esac
  cur="$(pinned_version "$tool")"
  latest="$(latest_release "$repo")"
  drift=false
  if [ -n "$latest" ] && [ "$latest" != "$cur" ]; then
    drift=true
    any_drift=true
  fi
  emit "${tool}_pinned" "$cur"
  emit "${tool}_latest" "$latest"
  emit "${tool}_drift" "$drift"
done
emit "any_drift" "$any_drift"
