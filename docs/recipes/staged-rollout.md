# Staged rollout

pleno-dlp's default (`--fail-on high`, see
[`docs/output-and-gating.md`](../output-and-gating.md)) already keeps
Medium-and-below noise (generic high-entropy, JWTs, PEM blobs, PII)
from failing a build. The recipe below is the next step: how to adopt
pleno-dlp on an existing repo without either drowning in triage or
quietly ignoring real findings forever.

## Stage 1 — audit (report-only)

Run the scan and upload the results without blocking anything. The
goal is to know what's in the repo before anyone is on the hook to
fix it.

```yaml
# .github/workflows/secret-scan.yml
- name: Scan filesystem (audit)
  run: |
    pleno-dlp scan filesystem . \
      --format sarif \
      --fail-on any \
      > findings.sarif
  continue-on-error: true   # never block merges in this stage

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: findings.sarif
```

Combined with `continue-on-error: true` the exit code is discarded,
so this stage is purely about getting every finding, including the
low/medium ones, into Code Scanning where a human can triage them.

Triage each finding into one of three buckets:

- A real credential that must be rotated. Rotate it, then remove it
  from history if it's in git (`scan git`) or from the working tree
  if it's filesystem-only.
- A real credential accepted as a risk, which is rare (e.g. a scoped
  read-only demo key that's meant to be public). Document why, then
  allowlist it.
- A false positive: add a narrow entry to `.pleno-allow.json` (see
  [`allowlist-patterns.md`](allowlist-patterns.md)), scoped to
  `detector` + `raw_regex` where possible instead of a broad path
  glob.

Stay in this stage until the audit run is quiet: every remaining
finding is either fixed or allowlisted with a `reason`.

## Stage 2 — gate on the default (critical + high)

Once the repo has a clean audit baseline, start blocking merges,
still gated on the built-in default rather than on everything:

```yaml
- name: Scan filesystem (gated)
  run: |
    pleno-dlp scan filesystem . \
      --format sarif \
      --allowlist .pleno-allow.json \
      > findings.sarif
    # no --fail-on: the default (high) already gates on named-secret
    # detector hits and verified/critical findings.
```

Drop `continue-on-error`.

If the team wants a stricter first gate than the built-in default,
pin it explicitly:

```yaml
- run: pleno-dlp scan filesystem . --allowlist .pleno-allow.json --fail-on critical
```

## Stage 3 — ratchet down to `--fail-on any`

With the allowlist mature and the team used to triaging pleno-dlp
findings, tighten the gate to block on every finding, including
Medium/low noise:

```yaml
- run: pleno-dlp scan filesystem . --allowlist .pleno-allow.json --fail-on any
```

## Combine with `--only-verified` for a zero-triage floor

```sh
pleno-dlp scan filesystem . --only-verified
```

See the severity table in
[`output-and-gating.md`](../output-and-gating.md).

## Summary

| Stage | `--fail-on` | Blocks merges? | When to move on |
|---|---|---|---|
| 1. Audit | `any` + `continue-on-error: true` | No | Backlog triaged to zero (fixed or allowlisted) |
| 2. Gate default | *(omit — defaults to `high`)* or `critical` | Yes, named/verified only | Allowlist stable, false-positive rate low |
| 3. Ratchet | `any` | Yes, everything | Team is comfortable triaging Medium/low noise |
