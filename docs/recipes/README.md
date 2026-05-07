# Recipes

Practical patterns for adopting pleno-dlp:

- [`github-actions.md`](github-actions.md) — workflow that uploads
  SARIF to GitHub Code Scanning, gates merges with `--fail-on`, and
  scans only the diff on PRs.
- [`pre-commit.md`](pre-commit.md) — local-machine secret-and-PII
  hook via [pre-commit](https://pre-commit.com/).
- [`gitlab-ci.md`](gitlab-ci.md) — GitLab CI pipeline writing SAST
  reports.
- [`allowlist-patterns.md`](allowlist-patterns.md) — common false-
  positive shapes and the matching allowlist entries.

Have a recipe to share? PRs welcome.
