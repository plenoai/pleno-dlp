# Hooks (claude-code, cursor, git)

`pleno-dlp hooks install claude-code|cursor` wires up a secret scan
directly into an AI coding agent's own hook mechanism, so a
credential the agent is about to write (or commit) gets flagged before it
lands.

```sh
pleno-dlp hooks install claude-code
pleno-dlp hooks install cursor
```

Both are idempotent: rerunning either command changes nothing unless
pleno-dlp's own binary path moved, in which
case the hook's embedded path is refreshed in place. Remove either with:

```sh
pleno-dlp hooks uninstall claude-code
pleno-dlp hooks uninstall cursor
```

Uninstall only touches the entry pleno-dlp itself registered — any other
hooks already configured for that tool are left alone.

## Why `--no-verify`

Both hooks run the `scan stdin --no-verify` pipeline in-process (see
[`--no-verify`](#the---no-verify-flag) below). Verification is never
attempted: the scan runs fully offline, without the network round-trip
that would put a hook in an agent's or developer's way, and every
finding's verdict comes back **unverified**. The verified,
git-staged-paths-only pre-commit recipe lives in
[`docs/recipes/pre-commit.md`](recipes/pre-commit.md), and `--fail-on` /
`--only-verified` CI gating in
[`docs/output-and-gating.md`](output-and-gating.md).

## What gets installed

### claude-code

- `.claude/hooks/pleno-dlp-scan.sh` — a generated wrapper that execs the
  resolved `pleno-dlp` binary as `hooks run claude-code`.
- A `PreToolUse` entry in `.claude/settings.json`, matching the `Edit`
  and `Write` tools, pointing at that script.

Claude Code pipes the tool call to the script on stdin before the edit
is applied. The hook concatenates and scans all about-to-be-written
text in the payload: `tool_input.content` for Write,
`tool_input.new_string` for Edit, and each
`tool_input.edits[].new_string` for MultiEdit.
If pleno-dlp finds a potential secret it exits 2, which
Claude Code treats as "block this tool call" and shows the reason (via
stderr) to the agent. A clean scan, or any failure in the hook's own
plumbing (unparseable payload, pleno-dlp not resolvable), allows the
edit through.

### cursor

- `.cursor/hooks/pleno-dlp-scan.sh` — the same kind of wrapper script.
- A `beforeShellExecution` entry in `.cursor/hooks.json`.

Cursor's direct analogue of claude-code's `PreToolUse` is the
`afterFileEdit` hook, which is documented as observation-only. So
pleno-dlp installs into `beforeShellExecution` instead: the one place
Cursor's hook API can block anything, which makes this closer to a
pre-commit hook than an edit-time one. It gates any shell command
mentioning both `git` and `commit` as whole words. That match
deliberately over-reaches, catching forms like `git -C repo commit`
while also scanning the rare non-commit command that happens to contain
both words. The script scans the command; when it looks like `git
commit`, it runs `git diff --cached` in the hook's reported working
directory, scans that diff offline, and denies the command on a finding
and allows it otherwise. Shell commands not mentioning both words are
allowed immediately.

**Not yet covered for cursor:** an edit-time equivalent of claude-code's
`PreToolUse` block.

## The `--no-verify` flag

`pleno-dlp scan <kind> --no-verify` skips every detector's `Verify()`
network round-trip at the engine level. Findings are still emitted,
always with verdict `unverified`. A verdict of `indeterminate` never
appears under this flag: `indeterminate` means a verification attempt
was made and failed, and `--no-verify` makes no attempt. The flag is
mutually exclusive with `--only-verified` and works against any scan
kind.

## git (native pre-commit)

`pleno-dlp hooks install git` replaces a gitleaks pre-commit hook without
the `pre-commit` framework. `hooks run git` is
[`pleno-dlp protect`](recipes/pre-commit.md#without-the-pre-commit-framework)
plus hook ergonomics. Both commands use the same diff collection,
transform, and in-process scan. The hook adds the following:

- a stderr list with masked values and `path:line` for each finding,
- the blocked-commit message,
- exit 0 with a warning when the hook itself fails.

The hook always scans offline. `protect` verifies findings unless
`--no-verify` is passed.

```sh
pleno-dlp hooks install git                 # blocks on high and critical
pleno-dlp hooks install git --fail-on any   # blocks on every finding
pleno-dlp hooks uninstall git
```

### What install writes

Install writes one file, `pre-commit`, into the directory printed by
`git rev-parse --git-path hooks`. That directory honours `core.hooksPath`
(local or global) and linked worktrees, and install prints the resolved
path. The script carries the marker line `# pleno-dlp-git-hook` and execs
the absolute path of the installing binary as
`hooks run git --fail-on '<level>'`.

- When `pre-commit` already exists without the marker, install refuses
  and leaves the file unchanged. Merge the last line of
  `pleno-dlp hooks print git` into that hook by hand.
- Rerunning install with the same binary and threshold changes nothing.
  When the binary path or `--fail-on` differs, install rewrites the file.
- Uninstall deletes the file only when it carries the marker.

### Hooks managed outside the repository

`pleno-dlp hooks print git [--fail-on X]` prints a script that resolves
`pleno-dlp` from `PATH` instead of embedding an absolute path. When the
binary is missing, the script prints one warning and exits 0, so a hook
shared through dotfiles does not block commits on machines without
pleno-dlp.

Plain global hooks directory:

```sh
git config --global core.hooksPath ~/.config/git/hooks
mkdir -p ~/.config/git/hooks
pleno-dlp hooks print git > ~/.config/git/hooks/pre-commit
chmod +x ~/.config/git/hooks/pre-commit
```

home-manager:

```nix
programs.git.hooks.pre-commit = pkgs.writeShellScript "pre-commit" ''
  if ! command -v pleno-dlp >/dev/null 2>&1; then
    echo 'pleno-dlp: not found on PATH; skipping staged secret scan' >&2
    exit 0
  fi
  exec pleno-dlp hooks run git --fail-on high
'';
```

A global `core.hooksPath` replaces each repository's `.git/hooks`, so
repository-local hooks stop running unless the global script chains to
them.

### What gets scanned

The hook and `protect` run
`git diff --cached --diff-filter=ACMR --no-color --no-ext-diff` in the
working directory. `protect --no-staged` drops `--cached`. Git sets that directory and the `GIT_DIR` /
`GIT_INDEX_FILE` environment, so `git commit -a` and alternate indexes
work. Before scanning, the hook transforms the diff as follows:

| Diff line | Treatment |
|---|---|
| `+` inside a hunk | Scanned, with the leading `+` removed |
| `-` inside a hunk | Dropped, so removing a secret is never blocked |
| context (` `) | Dropped, because the line is already committed |
| `+++ b/<path>` | Kept, to attribute findings to a path |
| other headers | Dropped |

The transformed text is scanned as one stdin-source buffer under the
`protect` scan kind. The hook maps each finding's byte offset back to
`<path>:<line>` in the staged file. The cursor hook collects its staged
diff with the same transform.

### Exit behaviour and `--fail-on`

`--fail-on` takes the same values as `scan --fail-on`: `any`, `info`,
`low`, `medium`, `high` (default), and `critical`. Findings at or above
the threshold block the commit with exit 1. The hook prints the findings
to stderr as follows:

```text
pleno-dlp: potential secrets in staged changes (offline, unverified scan):
  high     AWS                      AKIA..       leak.env:1
pleno-dlp: blocked commit (1 findings at or above high). Bypass once with git commit --no-verify; allowlist known fixtures in .pleno-allow.json (see docs/recipes/pre-commit.md).
```

The masked column shows at most six leading characters of the shared
safe `redacted` field (see the [detector display contract](redaction.md)). The hook never appends marker characters that
could reconstruct a short raw match.

An empty staged diff exits 0 silently. When git is missing, the
directory is not a repository, or the in-process scan fails, the hook
prints a warning and exits 0, so a pleno-dlp failure never blocks a
commit.
