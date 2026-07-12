# action smoke fixture

This directory is the scan target for the `action-test` workflow.

Its only job is to give the composite action in `action.yml` a small,
deterministic, secret-free tree to scan end to end: download the pinned
release binary, cosign-verify it, run a scan, and confirm the SARIF report
is well formed and reports no findings above the fail-on threshold.

Do not put anything secret-shaped here — no API keys, tokens, hashes,
base64 blobs, or example credentials. The whole point is that a clean scan
exits zero. Documentation that must show what real credentials look like
lives under `docs/`, which is deliberately not the smoke target: a secrets
scanner's own reference material contains secret-shaped strings by design
and can never be guaranteed clean.

Keep this file prose only.
