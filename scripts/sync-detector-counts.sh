#!/usr/bin/env bash
# Rewrite every published detector count (README, website, docs/counts.md,
# docs/verify-coverage.md) from the live registry. Run after adding,
# removing, or reclassifying a detector; TestPublishedCountsMatchSource
# (pkg/detectors/counts_test.go) is the gate that this script satisfies.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
json=$(go run ./cmd/pleno-dlp detectors list --format json)
total=$(jq length <<<"$json")
verified=$(jq '[.[] | select(.verifies)] | length' <<<"$json")
unverified=$((total - verified))
# class (c) verify gaps are listed explicitly; (b) is the remainder.
gap=$(grep -c '^type=[^ ]* class=c$' docs/verify-coverage.md || true)
bydesign=$((unverified - gap))
secret=$((total - 2)) # PIIAnonymize and PIIOpenAIPF
perl -0pi -e "s/\d+ built-in detector types/${total} built-in detector types/" README.md
perl -0pi -e "s/\*\*Current value:\*\* \d+ total \(\d+ verified, \d+ unverified-by-design\)/**Current value:** ${total} total (${verified} verified, ${unverified} unverified-by-design)/" docs/counts.md
perl -0pi -e "s/Total = \d+: \d+ secret/Total = ${total}: ${secret} secret/; s/## \(a\) Verify implemented — \d+ detectors/## (a) Verify implemented — ${verified} detectors/; s/## \(b\) Unverified-by-design — \d+ detectors/## (b) Unverified-by-design — ${bydesign} detectors/; s/^total=\d+\$/total=${total}/m; s/^a=\d+\$/a=${verified}/m; s/^b=\d+\$/b=${bydesign}/m; s/^c=\d+\$/c=${gap}/m" docs/verify-coverage.md
perl -0pi -e "s/pleno-dlp detects \d+ types/pleno-dlp detects ${total} types/; s/\d+ detectors\. Live verification/${total} detectors. Live verification/; s/\d+ detector types, (\d+) sources/${total} detector types, \1 sources/; s/\d+ of \d+ detectors check/${verified} of ${total} detectors check/" website/index.html
echo "total=${total} verified=${verified} unverified=${unverified}"
