# Pre-commit hook

[`pre-commit`](https://pre-commit.com/) downloads pleno-dlp via `go
install` so contributors don't need to vendor a binary. Add to
`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/plenoai/pleno-dlp
    rev: v0.45.0     # pin to a released tag
    hooks:
      - id: pleno-dlp
```

The hook runs `pleno-dlp scan filesystem` against the
pre-commit-staged paths only with `--fail-on high` so unverified
secrets and PII block the commit but lower-severity findings (like
high-entropy strings near keywords) surface as warnings without
blocking.

## Bypass for an emergency

```sh
git commit --no-verify -m "fix prod"
```

Bypassing must always be exceptional — log a follow-up issue to
either rotate the leaked secret or add it to `.pleno-allow.json` if
it's a known-noise pattern.

## Deeper local scan

The pre-commit hook scans only staged paths. Run a full repo scan
periodically:

```sh
pleno-dlp scan filesystem .
pleno-dlp scan git --repo . --max-depth 1000
```

## Allowlist for known fixtures

Place `.pleno-allow.json` at the repo root:

```json
{
  "entries": [
    {"detector": "AWS", "raw": "AKIAIOSFODNN7EXAMPLE",
     "reason": "trufflehog dummy"},
    {"path": "fixtures/**/*.env",
     "reason": "local test fixtures"},
    {"raw_regex": "^sk-test_",
     "reason": "Stripe test-mode keys"}
  ]
}
```

The hook auto-discovers this file from cwd up to 8 directories.
