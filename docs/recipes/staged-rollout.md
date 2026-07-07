# Staged rollout: audit first, then ratchet the gate down

A scanner that blocks CI on day one, on a repo nobody has triaged yet,
gets disabled by the first frustrated engineer who hits a false
positive. pleno-dlp's default (`--fail-on high`, see
[`docs/output-and-gating.md`](../output-and-gating.md)) already keeps
Medium-and-below noise (generic high-entropy, JWTs, PEM blobs, PII)
from failing a build. The recipe below is the next step: how to adopt
pleno-dlp on an existing repo without either drowning in triage or
quietly ignoring real findings forever.

## Stage 1 — audit (report-only)

Run the scan, upload results, block nothing. The goal is visibility:
know what's in the repo before anyone is on the hook to fix it.

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

`--fail-on any` here is deliberate even though it's the "block on
everything" setting elsewhere in this doc set — combined with
`continue-on-error: true` the exit code is discarded, so this stage is
purely about getting every finding, including the low/medium ones,
into Code Scanning where a human can triage them. Skip
`continue-on-error` and you've silently jumped to Stage 3.

Triage each finding into one of three buckets:

- **Real, must rotate** — rotate the credential, then remove it from
  history if it's in git (`scan git`), or from the working tree if
  it's filesystem-only.
- **Real, accepted risk** (rare — e.g. a scoped read-only demo key
  that's meant to be public) — document why, then allowlist it.
- **False positive** — add a narrow entry to `.pleno-allow.json` (see
  [`allowlist-patterns.md`](allowlist-patterns.md)). Don't allowlist by
  broad path glob; scope to `detector` + `raw_regex` where possible.

Stay in this stage until the audit run is quiet: every remaining
finding is either fixed or allowlisted with a `reason`.

## Stage 2 — gate on the default (critical + high)

Once the repo has a clean audit baseline, start blocking merges — but
still on the built-in default, not on everything:

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

Drop `continue-on-error`. New commits that introduce a named-secret
detector hit or a verified live credential now fail CI; Medium/low
noise (that the audit stage already worked through once) still
doesn't block, so contributors aren't retriaging entropy-string false
positives on every PR.

If the team wants a stricter first gate than the built-in default —
for example, blocking only on provider-confirmed live credentials
while the allowlist is still being built out — pin it explicitly:

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

At this point pleno-dlp behaves the way `--fail-on any` did before
#250 — but the team reached it on purpose, with an allowlist already
absorbing the known-noise patterns, instead of inheriting it as an
unannounced default on day one.

## Combine with `--only-verified` for a zero-triage floor

Independent of which `--fail-on` stage you're in, `--only-verified`
restricts everything (output, counts, exit code, `--revoke-on-verified`)
to provider-confirmed findings:

```sh
pleno-dlp scan filesystem . --only-verified
```

`--only-verified` drops every unverified finding before it reaches the
counter or the exit-code gate, and every verified finding is Critical
by definition (see the severity table in
[`output-and-gating.md`](../output-and-gating.md)), so the default
`--fail-on=high` already blocks on all of them without needing
`--fail-on critical` explicitly.

This is the closest thing to a "no false positives, ever" gate — a
verified finding means the credential authenticated against the
provider's API — and is a reasonable Stage-0 gate to run alongside the
audit stage above, before triage capacity exists for unverified
findings at all.

## Summary

| Stage | `--fail-on` | Blocks merges? | When to move on |
|---|---|---|---|
| 1. Audit | `any` + `continue-on-error: true` | No | Backlog triaged to zero (fixed or allowlisted) |
| 2. Gate default | *(omit — defaults to `high`)* or `critical` | Yes, named/verified only | Allowlist stable, false-positive rate low |
| 3. Ratchet | `any` | Yes, everything | Team is comfortable triaging Medium/low noise |
