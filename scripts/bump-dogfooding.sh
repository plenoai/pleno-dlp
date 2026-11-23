#!/usr/bin/env bash
# Move the aqua dogfooding pins (docs/dogfooding.md) to the newest pleno-dlp
# release that ships darwin/arm64 and the newest plenoai/aqua-registry main
# commit, then refresh aqua/aqua-checksums.json. Requires gh and aqua.
set -euo pipefail
cd "$(dirname "$0")/.."

version=""
for tag in $(gh release list -R plenoai/pleno-dlp --exclude-drafts --exclude-pre-releases -L 10 --json tagName -q '.[].tagName'); do
  if gh release view "$tag" -R plenoai/pleno-dlp --json assets -q '.assets[].name' | grep -qx 'pleno-dlp_darwin_arm64.tar.gz'; then
    version="$tag"
    break
  fi
done
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "no release with darwin/arm64 assets" >&2; exit 1; }
sha="$(gh api repos/plenoai/aqua-registry/commits/main -q .sha)"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "bad registry sha: $sha" >&2; exit 1; }

sed -i.bak -E "s|^(    ref: )[0-9a-f]{40}$|\1${sha}|; s|^(  - name: plenoai/pleno-dlp@)v[0-9.]+$|\1${version}|" aqua/aqua.yaml
rm aqua/aqua.yaml.bak
AQUA_POLICY_CONFIG="$PWD/aqua/aqua-policy.yaml" aqua -c aqua/aqua.yaml upc -prune
echo "pleno-dlp ${version}, plenoai/aqua-registry ${sha}"
