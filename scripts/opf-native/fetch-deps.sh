#!/usr/bin/env bash
# Fetch the opf_native C sources (privacy-filter.cpp + its ggml submodule)
# at the commit SHAs pinned in pkg/piiengine/opfnative/deps.lock, verifying
# each resolved SHA and failing closed on any mismatch (ADR-0005 §A).
#
# Fetch only: cmake configure/build and the .a install into cdeps/ live in
# the `opf-native-lib` Makefile target so CI can cache the two steps apart.
# This runs only for an -tags opf_native build; the default pure-Go path
# never invokes it.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
lock="$repo_root/pkg/piiengine/opfnative/deps.lock"
dest="$repo_root/build/opf-native/privacy-filter.cpp"

[ -f "$lock" ] || { echo "fetch-deps: missing $lock" >&2; exit 1; }

pf_url="$(awk '$1=="privacy-filter.cpp"{print $2}' "$lock")"
pf_commit="$(awk '$1=="privacy-filter.cpp"{print $NF}' "$lock")"
ggml_commit="$(awk '$1=="ggml"{print $NF}' "$lock")"

[ -n "$pf_url" ] && [ -n "$pf_commit" ] && [ -n "$ggml_commit" ] || {
	echo "fetch-deps: incomplete pins in deps.lock" >&2; exit 1; }

mkdir -p "$(dirname "$dest")"
if [ ! -d "$dest/.git" ]; then
	git clone "$pf_url" "$dest"
fi
git -C "$dest" fetch --depth 1 origin "$pf_commit"
git -C "$dest" checkout --quiet "$pf_commit"

got_pf="$(git -C "$dest" rev-parse HEAD)"
[ "$got_pf" = "$pf_commit" ] || {
	echo "fetch-deps: privacy-filter.cpp SHA mismatch: got $got_pf want $pf_commit" >&2; exit 1; }

git -C "$dest" submodule update --init --recursive ggml
ggml_path="$(git -C "$dest" config --file .gitmodules --get-regexp 'path' | awk '/ggml/{print $2; exit}')"
ggml_path="${ggml_path:-ggml}"
got_ggml="$(git -C "$dest/$ggml_path" rev-parse HEAD)"
[ "$got_ggml" = "$ggml_commit" ] || {
	echo "fetch-deps: ggml SHA mismatch: got $got_ggml want $ggml_commit" >&2; exit 1; }

echo "opf-native-deps: verified privacy-filter.cpp@$got_pf ggml@$got_ggml"
