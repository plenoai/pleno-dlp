# Crash reports (opt-in)

pleno-dlp can send an anonymized report when it crashes. Sending is
**disabled by default** and is never enabled implicitly: no prompt, no CI
detection, no first-run banner. Whether or not sending is enabled, every
crash is written to a local spool so you can read it first.

## Enable, disable, inspect

```sh
pleno-dlp telemetry status       # enabled/disabled, source (file/env/default), endpoint, spool dir
pleno-dlp telemetry enable       # writes {"crash_reports": true} to telemetry.json
pleno-dlp telemetry disable      # writes {"crash_reports": false}; spool is kept
pleno-dlp telemetry show-last    # pretty-prints the most recent spooled report
pleno-dlp telemetry send <file>  # uploads one reviewed spool file as-is
```

`telemetry send` works even when sending is disabled: it is an explicit,
per-file action. It accepts only files that match the report schema exactly
(unknown fields are rejected), so it cannot be used to upload other files.

## Local-only reports (`--crash-report`)

For an offline or scripted run, `--crash-report <path>` writes a local,
secret-free report to the path you name when a command panics, without
sending anything:

```sh
pleno-dlp --crash-report /tmp/pleno-crash.json scan github --repo .
```

The file uses the same schema, redaction pipeline, and canonical encoding as
the spool above (`kind` is `crash`), so it is byte-identical to what
`pleno-dlp telemetry show-last` prints for the same report. It is written
`0600` (parent directories `0700`) and records the command path, recognised
flag names (never values), version, platform, and the redacted stack. Unlike
a telemetry report it is never sent. With `--crash-report` set the panic is
contained and the process exits non-zero; without it, crash behaviour is
unchanged (the telemetry path above still applies).

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
| `kind` | `panic` / `fatal` (seen by the supervisor), `recovered` (caught in-process), or `crash` (written by `--crash-report`) |
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

Applied to `message`, `stack`, and `command` before the report is written
(spooled by telemetry, or written to the `--crash-report` path):

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
