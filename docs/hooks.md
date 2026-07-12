# Agent hooks (claude-code, cursor)

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

Both hooks scan with `pleno-dlp scan stdin --no-verify` (see
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

## Measured latency

`pleno-dlp scan stdin --no-verify` against a representative small edit
(~450 bytes, one embedded AWS-key-shaped string, 30 lines), full process
spawn included:

| Path                                             | median | p90    |
|---------------------------------------------------|--------|--------|
| `pleno-dlp scan stdin --no-verify` (bare)          | 22.8ms | 26.1ms |
| `pleno-dlp hooks run claude-code` (end-to-end)     | 44.8ms | 50.9ms |

The `hooks run` path costs roughly 2x the bare scan because it spawns
`scan stdin` as a nested subprocess — see the comment on `scanOffline`
in `cmd/pleno-dlp/cmd/hooks.go`.

Reproduce:

```sh
go build -o /tmp/pleno-dlp ./cmd/pleno-dlp
printf '...' > /tmp/sample.txt   # your representative content
time /tmp/pleno-dlp scan stdin --no-verify --quiet --fail-on any --format json < /tmp/sample.txt
```
