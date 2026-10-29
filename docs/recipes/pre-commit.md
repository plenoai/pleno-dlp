# Pre-commit hook

[`pre-commit`](https://pre-commit.com/) downloads pleno-dlp via `go
install` so contributors don't need to vendor a binary. Add to
`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/plenoai/pleno-dlp
    rev: v0.53.0     # pin to a released tag
    hooks:
      - id: pleno-dlp
```

The hook runs `pleno-dlp scan filesystem` against the
pre-commit-staged paths only with `--fail-on high`. Pass `--fail-on
any` to also block on Medium-and-below noise
once the repo has an allowlist tuned — see
[`staged-rollout.md`](staged-rollout.md).

## Without the pre-commit framework

```sh
pleno-dlp hooks install git            # writes <git-dir>/hooks/pre-commit
pleno-dlp hooks print git > hook.sh    # for core.hooksPath, home-manager, lefthook
```

The hook is `pleno-dlp protect` plus hook ergonomics: a masked
`path:line` list, a blocked-commit message, and exit 0 when the hook
itself fails. It scans only lines that the commit adds, runs offline, and
blocks on `high` or above by default. For CI or a scripted check that
needs `--format`, verification, or detector filters, run `protect`
directly. [`docs/hooks.md`](../hooks.md#git-native-pre-commit)
describes the diff transform, `--fail-on`, and the behaviour when the
hook itself fails.

### Migrating from gitleaks

| gitleaks | pleno-dlp |
|---|---|
| `gitleaks git --staged --redact` (pre-commit) | `pleno-dlp hooks run git` (installed by `hooks install git`) |
| `gitleaks git --staged` (scripted or CI) | `pleno-dlp protect` (`--format json\|sarif`, `--fail-on`, `--no-verify`) |
| `gitleaks git --pre-commit` (unstaged) | `pleno-dlp protect --no-staged` |
| `.gitleaksignore` / `[allowlist]` | `.pleno-allow.json` (below) |
| `--no-verify` bypass | `git commit --no-verify` (unchanged) |

`--redact` has no pleno-dlp equivalent because the hook always masks.
The JSON output includes a safe `redacted` rendering and a SHA-256
`secret_hash`; table and hook output show only the safe rendering. Output
boundaries check the rendering against both `Raw` and `RawV2` and replace
it with a common mask when it contains either full value. The hook limits
that safe rendering to its first six characters without adding a suffix.

Remove the gitleaks hook before installing, because `hooks install git`
refuses to overwrite a `pre-commit` file that pleno-dlp did not write.

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
    {"detector": "Stripe", "raw_regex": "^sk_test_",
     "reason": "Stripe test-mode keys"}
  ]
}
```

The hook auto-discovers this file from cwd up to 8 directories.

`hooks install git` scans the staged diff as stdin, so `path` entries do
not match its findings. Use `detector` + `raw` or `raw_regex` entries for
fixtures that the git hook must allow.
