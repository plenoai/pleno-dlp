# Crash reports (opt-in)

pleno-dlp can send an anonymized report when it crashes. Sending is
**disabled by default** and is never enabled implicitly: no prompt, no CI
detection, no first-run banner. Whether or not sending is enabled, every
crash is written to a local spool so you can read it first.

## Enable, disable, inspect

```sh
pleno-dlp telemetry status       # crash opt-in + that feedback ignores it, source, endpoint, spool dir
pleno-dlp telemetry enable       # writes {"crash_reports": true} to telemetry.json
pleno-dlp telemetry disable      # writes {"crash_reports": false}; spool is kept
pleno-dlp telemetry show-last    # pretty-prints the most recent spooled report
pleno-dlp telemetry send <file>  # uploads one reviewed spool file as-is
```

`telemetry status` prints the crash opt-in and, separately, that
`pleno-dlp feedback` always sends and ignores that opt-in.

`telemetry send` works even when sending is disabled: it is an explicit,
per-file action. It accepts only files that match the report schema exactly
(unknown fields are rejected), so it cannot be used to upload other files.

## Feedback

`pleno-dlp feedback` sends a short message to the same relay. It **ignores
the crash opt-in**: running the command is the consent, so it sends even when
crash reports are disabled.

```sh
pleno-dlp feedback "the --format sarif flag saved my afternoon"
echo "please add a Jira label filter" | pleno-dlp feedback --yes
```

The message is read from the arguments, or from stdin when none are given.
Before sending, the same redaction pipeline as crash reports runs over the
message (URLs, emails, IPs, absolute paths, tokens, and any built-in secret
detector match). Without `--yes`, an interactive prompt confirms the send; a
non-interactive invocation must pass `--yes`. Feedback is also subject to the
local throttle below.

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
| Opt-in | `crash_reports` in `<config>/pleno-dlp/telemetry.json` | `false` |
| Opt-in override | `PLENO_DLP_CRASH_REPORTS=0` or `=1` (wins over the file) | unset |
| Endpoint | `endpoint` in `telemetry.json`, or `PLENO_DLP_CRASH_ENDPOINT` (wins) | `https://crash.plenoai.com/v1/pleno-dlp` |
| Config/spool root | `PLENO_DLP_TELEMETRY_DIR` | `os.UserConfigDir()/pleno-dlp` |

`<config>` is `os.UserConfigDir()`: `~/.config` (or `$XDG_CONFIG_HOME`) on
Linux, `~/Library/Application Support` on macOS, `%AppData%` on Windows.
The endpoint must be `https`; plain `http` is accepted only for loopback
hosts, for running a relay locally.

The default endpoint is a relay whose source is public in
[plenoai/plenoai.com](https://github.com/plenoai/plenoai.com) under
`workers/crash-relay`. Point `endpoint` at your own relay to keep reports
inside your organization.

## What a report contains

Every field is listed here; there are no others.

| Field | Content |
|---|---|
| `schema` | `pleno-dlp.crash/v1` |
| `fingerprint` | 16 hex chars of SHA-256 over the digit-normalized message and the top five in-module function names; stable across versions and line moves |
| `version`, `commit` | build metadata |
| `goos`, `goarch`, `go_version` | platform and toolchain |
| `command` | subcommand words only, e.g. `scan filesystem` |
| `flags` | names of recognised flags only, e.g. `["format"]`; never values |
| `kind` | `panic` / `fatal` (seen by the supervisor) or `recovered` (caught in-process) |
| `message` | the redacted panic or fatal-error line |
| `stack` | the redacted goroutine dump |
| `created_at` | UTC, truncated to the minute |

Example (produced by `pleno-dlp telemetry crash-test --goroutine`):

```json
{
  "schema": "pleno-dlp.crash/v1",
  "fingerprint": "527f8de5bcffdad9",
  "version": "1.4.0",
  "commit": "3f2c1ab",
  "goos": "darwin",
  "goarch": "arm64",
  "go_version": "go1.26.9",
  "command": "telemetry crash-test",
  "flags": ["goroutine"],
  "kind": "panic",
  "message": "panic: pleno-dlp telemetry crash-test (goroutine)",
  "stack": "goroutine [running]:\ngithub.com/plenoai/pleno-dlp/cmd/pleno-dlp/cmd.init.func7.1()\n\tgithub.com/plenoai/pleno-dlp/cmd/pleno-dlp/cmd/telemetry.go:147\ncreated by github.com/plenoai/pleno-dlp/cmd/pleno-dlp/cmd.init.func7 in goroutine N\n\tgithub.com/plenoai/pleno-dlp/cmd/pleno-dlp/cmd/telemetry.go:147\n",
  "created_at": "2026-10-18T11:41:00Z"
}
```

### Never collected

Hostname, username, working directory, environment variables, positional
arguments (paths, URLs, repository names), flag values, scanned content,
findings, IP addresses, and machine identifiers. The relay necessarily sees
the client IP of the HTTP connection; what it retains is defined by the
relay's public source.

### Redaction pipeline

Applied to `message`, `stack`, and `command` before the report is spooled:

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

The marshalled report is capped at 32 KiB; the stack tail is truncated with
a `...[truncated]` marker.

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

Reports are written to `<root>/crash/last.json` and
`<root>/crash/<fingerprint>-<unix>.json`. The directory is `0700`, files are
`0600`, and at most 20 per-crash files are kept (oldest pruned).

## Local throttling

The client keeps its own best-effort limit in `<root>/throttle.json` so a
crash loop or a scripted `pleno-dlp feedback --yes` cannot lean entirely on
the relay's per-address limit:

- an automatic crash upload is sent at most once per fingerprint per hour;
- at most 5 feedback uploads are sent per hour.

Explicit `telemetry send <file>` is a per-file action and is not throttled.
The state file is best-effort: an unreadable or corrupt file is ignored, and
a throttle that cannot be written fails open so it never blocks a report.

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
