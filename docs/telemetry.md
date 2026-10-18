# Crash reports and feedback

pleno-dlp can send three kinds of anonymized report through one channel:

| Kind | Created by | Consent |
|---|---|---|
| `crash` | pleno-dlp itself, when it panics or hits a runtime fatal error | opt-in: `pleno-dlp telemetry enable` (disabled by default) |
| `feedback` | you, with `pleno-dlp feedback "..."` | the command itself, confirmed per invocation |
| `false-positive` | you, with `pleno-dlp feedback --kind false-positive --detector <Type> "..."` | the command itself, confirmed per invocation |

Crash sending is never enabled implicitly: no prompt, no CI detection, no
first-run banner. Whether or not it is enabled, every crash is written to a
local spool so you can read it first. Feedback and false-positive reports
need no opt-in because you run the command and confirm the exact payload;
they still use the configured endpoint.

Reports are relayed into the **private** repository
`plenoai/pleno-dlp-intake`; only pleno-dlp maintainers can read them. The
client talks only to the relay, never to GitHub, and sends no credentials.

## Sending feedback

```sh
pleno-dlp feedback "the SARIF output is missing rule help text"
pleno-dlp feedback --kind false-positive --detector AWS "matches AKIAIOSFODNN7EXAMPLE in docs"
pleno-dlp feedback --file notes.txt --dry-run     # print the exact payload, send nothing
git log -1 --format=%B | pleno-dlp feedback --stdin --yes
```

| Flag | Meaning |
|---|---|
| `--kind feedback\|false-positive` | report kind (default `feedback`) |
| `--detector <Type>` | required for `false-positive`, rejected otherwise; must be a Type from `pleno-dlp detectors list` |
| `--file <path>` / `--stdin` | read the message from a file or stdin (at most 64 KiB) instead of arguments; exactly one source is allowed |
| `--dry-run` | print the exact redacted JSON to stdout and exit 0 without sending |
| `--yes` | skip the confirmation prompt (required with `--stdin`) |

The command redacts the message, prints the payload to stderr, then asks
`Send this anonymized report? [y/N]` on the terminal. Without a terminal
and without `--yes` it refuses. A message that is empty after redaction is
never sent. On success it prints
`<kind> report recorded as <issue URL> (private intake)` when the relay
returns an issue link (the link opens only for maintainers), otherwise
`<kind> report sent to <endpoint>`. On failure the report is spooled and
the `pleno-dlp telemetry send <path>` retry command is printed; the exit
status is non-zero.

## Managing crash reports and the spool

```sh
pleno-dlp telemetry status       # crash opt-in, its source (file/env/default), endpoint, spool dir
pleno-dlp telemetry enable       # writes {"crash_reports": true} to telemetry.json
pleno-dlp telemetry disable      # writes {"crash_reports": false}; spool is kept
pleno-dlp telemetry show-last    # pretty-prints the most recent spooled report of any kind
pleno-dlp telemetry send <file>  # uploads one reviewed spool file of any kind
```

`telemetry send` works even when crash sending is disabled: it is an
explicit, per-file action. It accepts only files that match the report
schema exactly (unknown fields and per-kind contract violations are
rejected), so it cannot be used to upload other files.

## Local-only reports (`--crash-report`)

For an offline or scripted run, `--crash-report <path>` writes a local,
secret-free report to the path you name when a command panics, without
sending anything:

```sh
pleno-dlp --crash-report /tmp/pleno-crash.json scan github --repo .
```

The file is written `0600` (parent directories `0700`) and records the
command path, recognised flag names (never values), version, platform, and
the stack trace. It does not run the telemetry redaction pipeline, so treat
the file like a crash log; unlike a telemetry report it is never sent. With
`--crash-report` set the panic is contained and the process exits non-zero;
without it, crash behaviour is unchanged (the telemetry path above still
applies).

## Configuration

| Setting | Where | Default |
|---|---|---|
| Crash opt-in | `crash_reports` in `<config>/pleno-dlp/telemetry.json` | `false` |
| Crash opt-in override | `PLENO_DLP_CRASH_REPORTS=0` or `=1` (wins over the file) | unset |
| Endpoint (all kinds) | `endpoint` in `telemetry.json`, or `PLENO_DLP_TELEMETRY_ENDPOINT` (wins) | `https://intake.plenoai.com/v1/pleno-dlp` |
| Config/spool root | `PLENO_DLP_TELEMETRY_DIR` | `os.UserConfigDir()/pleno-dlp` |

`<config>` is `os.UserConfigDir()`: `~/.config` (or `$XDG_CONFIG_HOME`) on
Linux, `~/Library/Application Support` on macOS, `%AppData%` on Windows.
The endpoint must be `https`; plain `http` is accepted only for loopback
hosts, for running a relay locally. Point `endpoint` at your own relay to
keep reports inside your organization. v0.67's `PLENO_DLP_CRASH_ENDPOINT`
is no longer read.

## What a report contains

Schema `pleno-dlp.report/v1`. Every key below is present in every report;
a field that does not apply to the kind is the empty string. There are no
other fields.

| Field | crash | feedback | false-positive | Content |
|---|---|---|---|---|
| `schema` | yes | yes | yes | `pleno-dlp.report/v1` |
| `kind` | yes | yes | yes | `crash`, `feedback`, or `false-positive` |
| `crash_kind` | yes | `""` | `""` | `panic` / `fatal` (seen by the supervisor) or `recovered` (caught in-process) |
| `fingerprint` | yes | `""` | `""` | 16 hex chars of SHA-256 over the digit-normalized message and the top five in-module function names; stable across versions and line moves |
| `version`, `commit` | yes | yes | yes | build metadata |
| `goos`, `goarch`, `go_version` | yes | yes | yes | platform and toolchain |
| `command` | yes | `feedback` | `feedback` | subcommand words only, e.g. `scan filesystem` |
| `flags` | yes | yes | yes | names of flags that were set, e.g. `["format"]`; never values |
| `message` | yes | yes | yes | crash: the redacted panic or fatal-error line; otherwise your redacted text |
| `stack` | yes | `""` | `""` | the redacted goroutine dump |
| `detector` | `""` | `""` | yes | detector Type name as in `pleno-dlp detectors list` |
| `created_at` | yes | yes | yes | UTC, truncated to the minute |

Crash example (produced by `pleno-dlp telemetry crash-test --goroutine`):

```json
{
  "schema": "pleno-dlp.report/v1",
  "kind": "crash",
  "crash_kind": "panic",
  "fingerprint": "527f8de5bcffdad9",
  "version": "1.4.0",
  "commit": "3f2c1ab",
  "goos": "darwin",
  "goarch": "arm64",
  "go_version": "go1.26.9",
  "command": "telemetry crash-test",
  "flags": ["goroutine"],
  "message": "panic: pleno-dlp telemetry crash-test (goroutine)",
  "stack": "goroutine [running]:\ngithub.com/plenoai/pleno-dlp/cmd/pleno-dlp/cmd.init.func7.1()\n\tgithub.com/plenoai/pleno-dlp/cmd/pleno-dlp/cmd/telemetry.go:147\n",
  "detector": "",
  "created_at": "2026-10-18T11:41:00Z"
}
```

False-positive example (`pleno-dlp feedback --kind false-positive --detector AWS --dry-run "AKIA example in /Users/alice/docs/x.md"`):

```json
{
  "schema": "pleno-dlp.report/v1",
  "kind": "false-positive",
  "crash_kind": "",
  "fingerprint": "",
  "version": "1.4.0",
  "commit": "3f2c1ab",
  "goos": "darwin",
  "goarch": "arm64",
  "go_version": "go1.26.9",
  "command": "feedback",
  "flags": ["detector", "dry-run", "kind"],
  "message": "AKIA example in $HOME/docs/x.md",
  "stack": "",
  "detector": "AWS",
  "created_at": "2026-10-18T11:41:00Z"
}
```

### Never collected

Hostname, username, working directory, environment variables, positional
arguments of other commands (paths, URLs, repository names), flag values,
scanned content, findings, IP addresses, and machine identifiers. For
feedback, the only free text is the message you wrote, after redaction.
The relay necessarily sees the client IP of the HTTP connection.

### Redaction pipeline

Applied to `message`, `stack`, and `command` of every kind before the report
is previewed, spooled, or sent:

1. Drop `+0x…` PC offsets, replace hex addresses and arguments with `0x?`,
   rewrite `goroutine 17 [running]:` to `goroutine [running]:`.
2. Replace URLs with `[URL]`, except `github.com/plenoai/...`, which keeps
   only `https://github.com/plenoai`.
3. Rewrite frames to module-relative paths (`github.com/plenoai/pleno-dlp/…`),
   then `$HOME`, `$GOPATH`, `$GOMODCACHE`, and `$GOROOT` prefixes.
4. Replace emails (`[EMAIL]`), IPv4/IPv6 addresses (`[IP]`), remaining
   absolute paths (`[PATH]`), and long hex or high-entropy alphanumeric
   runs of 20+ characters (`[TOKEN]`).
5. Run every built-in secret detector offline (never verified) over the
   result and replace each match with `[REDACTED:<Detector>]`.

Bounds: `message` at most 2048 bytes, `stack` at most 24 KiB, and the
encoded report at most 32 KiB. Truncated fields end in a `...[truncated]`
marker. Redaction is pattern- and detector-based: it removes what it
recognizes, so do not paste data you would not want maintainers to read.

## How crashes are captured

- **Sending enabled.** pleno-dlp re-executes itself as a child with the same
  arguments (`PLENO_DLP_CRASH_CHILD=1`), inherits stdin/stdout, tees stderr,
  and forwards SIGINT/SIGTERM. When the child exits with status 2 and its
  stderr carries a Go `panic:` or `fatal error:` dump, the parent builds,
  spools, and sends a report, then exits with the child's status (or
  128+signal). This catches panics in any goroutine and runtime fatal errors
  such as `concurrent map writes`. If re-exec fails, pleno-dlp runs
  in-process.
- **Sending disabled (default).** No child process is started. A panic on
  the main goroutine is recovered, spooled, and re-printed, and the process
  exits 2. Panics in other goroutines and runtime fatal errors are not
  captured in this mode.

## Spool

Reports are written to `<root>/reports/last.json` and
`<root>/reports/<kind>-<id>-<unix>.json`, where `<id>` is the crash
fingerprint, or for feedback and false-positive reports the first 16 hex
characters of the SHA-256 of the encoded report. Crashes are always
spooled; feedback is spooled only when sending fails. The directory is
`0700`, files are `0600`, and at most 20 per-report files are kept (oldest
pruned).

## Crash notice

With sending enabled:

```
pleno-dlp crashed; anonymized crash report <fingerprint> saved to <path> and sent. Inspect: pleno-dlp telemetry show-last. Opt out: pleno-dlp telemetry disable.
```

(" and sent" is omitted when the upload fails; a second line then prints the
error and the `telemetry send` command to retry.)

With sending disabled:

```
pleno-dlp crashed; report saved to <path>. Opt in to anonymous crash reports with: pleno-dlp telemetry enable
```
