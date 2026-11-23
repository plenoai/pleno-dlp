# Baselines, inline pragmas, and skip rules

pleno-dlp has one suppression policy (`engine.Allowlist`), applied after
dedup and the placeholder filter. Four inputs feed it, and each
suppressed finding is counted on stderr by reason
(`allowlist`, `baseline`, `inline-allow`). `--show-suppressed` emits the
suppressed findings with `suppressed_by` set instead of dropping them.

| Input | Scope | Use it for |
|---|---|---|
| `.pleno-allow.json` / `--allowlist` | detector, raw, `raw_regex`, `raw_contains`, path glob, `fingerprint` | Curated, reviewed exceptions |
| `--baseline <file>` | exact fingerprint | Adopting the scanner on a repository with existing findings |
| inline pragma | one line of content | Annotating a known test fixture next to the value |
| `--skip-regex`, `--skip-word` | raw secret | Ad-hoc runs; prefer the allowlist for anything permanent |

## Fingerprint

`fingerprint` (JSON) and `partialFingerprints["baseline/v1"]` (SARIF)
are the first 128 bits of SHA-256 over:

```
"pleno-dlp/fingerprint/v1" \0 lower(detector) \0 path \0 raw-secret
```

`path` is slash-separated and relative to the working directory when the
scanned file is beneath it. The fingerprint is stable across line moves,
verification results, severity changes, and commits. It differs when the
same secret appears in a different file, so a baselined fixture cannot
hide a copy that leaks elsewhere. To keep paths portable across CI
checkouts, run the scan from the repository root with a relative target
(`scan filesystem .`). Baselines never contain raw secrets.

## Workflow

```sh
# 1. Accept the current findings.
pleno-dlp scan filesystem . --format json --fail-on any | pleno-dlp baseline create

# 2. Gate only on new findings.
pleno-dlp scan filesystem . --baseline .pleno-baseline.json --fail-on any

# 3. Refresh: add new findings and prune fixed ones (--no-prune keeps them).
pleno-dlp scan filesystem . --format json --fail-on any | pleno-dlp baseline update
```

`baseline create` refuses to overwrite an existing file without
`--force`. `baseline update` reads a report generated without
`--baseline`, or with `--baseline --show-suppressed` (records suppressed
by the baseline are kept; records suppressed by other mechanisms are
ignored). Writes are atomic, so an interrupted update never leaves a
truncated baseline. The format is:

```json
{
  "version": 1,
  "findings": [
    {"fingerprint": "148d0ec0c83d049dd22b128c0a70592a", "detector": "GitHub", "path": "src/a.env", "redacted": "ghp_wWPw..."}
  ]
}
```

A baseline entry can also be written as an allowlist entry
(`{"fingerprint": "...", "reason": "..."}`) when the exception needs a
recorded rationale.

## Inline pragmas

Honored for every source whose content the engine scans directly —
`scan filesystem`, `scan git`, `scan stdin`, `protect`, and the git and
agent hooks:

```python
API_KEY = "<fixture value>"  # pleno-dlp:allow

# pleno-dlp:allow-next-line
API_KEY = "<fixture value>"
```

`pleno-dlp:allow` applies when it appears on the line that holds the
start or the end of the secret (so a multi-line PEM block can be
annotated on its closing line). `pleno-dlp:allow-next-line` applies to
the next line only. `kingfisher:ignore` and `gitleaks:allow` are
accepted on the same line for migration. Secrets found only after
decoding (for example base64) are not matched against pragmas.

A pragma is controlled by whoever can edit the scanned content. For
audits of untrusted repositories, pass `--no-inline-allow` so annotated
secrets are reported.

## Skip rules

`--skip-regex <go-regexp>` and `--skip-word <word>` (case-insensitive
substring) suppress findings by raw secret value and are repeatable.
They are equivalent to allowlist entries with `raw_regex` and
`raw_contains`, and are part of the `--incremental` state key.
