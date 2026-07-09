# Agent hooks (claude-code, cursor)

`pleno-dlp hooks install claude-code|cursor` wires up a latency-tolerant
secret scan directly into an AI coding agent's own hook mechanism, so a
credential the agent is about to write (or commit) gets flagged before it
lands — without waiting on CI. This is issue #303.

```sh
pleno-dlp hooks install claude-code
pleno-dlp hooks install cursor
```

Both are idempotent: rerunning either command prints "already installed"
and changes nothing unless pleno-dlp's own binary path moved, in which
case the hook's embedded path is refreshed in place. Remove either with:

```sh
pleno-dlp hooks uninstall claude-code
pleno-dlp hooks uninstall cursor
```

Uninstall only touches the entry pleno-dlp itself registered — any other
hooks already configured for that tool are left alone.

## Why `--no-verify`

Both hooks scan with `pleno-dlp scan stdin --no-verify` (see
[`--no-verify`](#the---no-verify-flag) below): verification is never
attempted, so every finding's verdict is **unverified** (not
`indeterminate` — that verdict specifically means an attempt was made
and failed; see `--only-verified` in
[`docs/output-and-gating.md`](output-and-gating.md)) rather than
confirmed live, in exchange for running fully offline with no network
round-trip. That trade only makes sense for a hook that has to stay out
of an agent's or developer's way — it is not a replacement for the fully
verified `pleno-dlp scan` gate CI should still run. See
[`docs/recipes/pre-commit.md`](recipes/pre-commit.md) for the
verified, git-staged-paths-only pre-commit recipe, and
[`docs/output-and-gating.md`](output-and-gating.md) for `--fail-on` /
`--only-verified` CI gating.

## What gets installed

### claude-code

- `.claude/hooks/pleno-dlp-scan.sh` — a generated wrapper that execs the
  resolved `pleno-dlp` binary as `hooks run claude-code`.
- A `PreToolUse` entry in `.claude/settings.json`, matching the `Edit`
  and `Write` tools, pointing at that script.

Claude Code pipes the tool call (`tool_input.content`: the file's new
content) to the script on stdin before the edit is applied. The script
scans it offline; if pleno-dlp finds a potential secret it exits 2, which
Claude Code treats as "block this tool call" and shows the reason (via
stderr) to the agent. A clean scan, or any failure in the hook's own
plumbing (unparseable payload, pleno-dlp not resolvable), allows the
edit through — the hook fails open rather than ever being able to wedge
every edit on its own bug.

### cursor

- `.cursor/hooks/pleno-dlp-scan.sh` — the same kind of wrapper script.
- A `beforeShellExecution` entry in `.cursor/hooks.json`.

Cursor's direct analogue of claude-code's `PreToolUse` — the
`afterFileEdit` hook — is documented as observation-only: it cannot deny
or otherwise stop an edit, only observe it after the fact. Of the three
Cursor hook events that *can* return a permission decision
(`beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`), this
installs into `beforeShellExecution` and gates specifically on `git
commit` invocations — closer to a pre-commit hook than an edit-time one,
but the one place Cursor's hook API can actually block something. The
script scans the command; when it looks like `git commit`, it runs `git
diff --cached` in the hook's reported working directory, scans that
diff offline, and returns `{"permission":"deny", ...}` on a finding or
`{"permission":"allow"}` otherwise. Every other shell command is
allowed immediately without paying the scan cost.

**Not yet covered for cursor:** an edit-time equivalent of claude-code's
`PreToolUse` block. If Cursor exposes a blocking pre-write hook in a
future release, `hooks install cursor` should move to it; today
`beforeShellExecution` intercepting `git commit` is the closest
well-specified, verified-blocking mechanism.

## The `--no-verify` flag

`pleno-dlp scan <kind> --no-verify` skips every detector's `Verify()`
network round-trip at the engine level (`pkg/engine.Options.NoVerify`)
— not just a post-hoc filter on the output. Findings are still emitted,
always with verdict `unverified` (verification is never attempted, so
it can't land on `indeterminate`, which means an attempt was made and
failed). It is mutually exclusive with `--only-verified` (which would
otherwise always report zero results, since nothing is ever
verified). This is the mechanism the hooks above depend on; it works
against any scan kind, not only `stdin`.

## Measured latency

`pleno-dlp scan stdin --no-verify` against a representative small edit
(~450 bytes, one embedded AWS-key-shaped string, 30 lines), full process
spawn included, on the machine used for this change:

| Path                                             | median | p90    |
|---------------------------------------------------|--------|--------|
| `pleno-dlp scan stdin --no-verify` (bare)          | 22.8ms | 26.1ms |
| `pleno-dlp hooks run claude-code` (end-to-end)     | 44.8ms | 50.9ms |

The `hooks run` path costs roughly 2x the bare scan because it spawns
`scan stdin` as a nested subprocess rather than re-implementing engine
wiring in-process — see the comment on `scanOffline` in
`cmd/pleno-dlp/cmd/hooks.go` for why that duplication was rejected.
Both numbers are well within pre-commit / per-edit latency tolerance;
neither includes the one-time cost of a cold `go install` binary's first
page-fault, which a warm hook path won't repeat.

Reproduce:

```sh
go build -o /tmp/pleno-dlp ./cmd/pleno-dlp
printf '...' > /tmp/sample.txt   # your representative content
time /tmp/pleno-dlp scan stdin --no-verify --quiet --fail-on any --format json < /tmp/sample.txt
```
