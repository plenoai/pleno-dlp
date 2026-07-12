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
- [`github-history-scan.md`](github-history-scan.md) — full commit
  history scanning (clone-based, zero per-repo REST cost), comments,
  auth, GHE clone-URL derivation, and API-call accounting.
- [`staged-rollout.md`](staged-rollout.md) — adopting pleno-dlp on an
  existing repo: audit → gate the default → ratchet to
  `--fail-on any`.

Have a recipe to share? PRs welcome.
