# Feedback

`pleno-dlp feedback` sends a short, redacted message to the maintainers. It
is user-initiated and never runs on its own: nothing leaves the machine until
you confirm at the terminal, or pass `--yes` in a script you control.

```sh
pleno-dlp feedback "scan of a 2 GB monorepo OOMs"
echo "docs typo in verify-coverage.md" | pleno-dlp feedback --stdin
```

## Local record

Every report is written to the spool before it is sent, so there is always a
local copy of exactly what left the machine — whether the upload succeeds or
not. Reports live under `<telemetry root>/feedback/`:

- `<root>/feedback/last.json` — the most recent report.
- `<root>/feedback/<fingerprint>-<unix>.json` — one per report.

The directory is `0700`, files are `0600`, and at most 20 per-report files
are kept (oldest pruned). `<root>` is the same directory crash reports use
(`PLENO_DLP_TELEMETRY_DIR`, else `os.UserConfigDir()/pleno-dlp`).

## Confirmation

Unless `--yes` is given, the message is previewed and you are asked to
approve the send:

```
<message>

Send this feedback report to https://feedback.plenoai.com/v1/pleno-dlp? [y/N]
```

The question is read from `/dev/tty`, not stdin. That is what lets you pipe
the message in with `--stdin` and still answer the prompt on the terminal:

```sh
printf 'the docs example is wrong' | pleno-dlp feedback --stdin
```

When there is no controlling terminal (CI, cron), the prompt falls back to an
interactive stdin; if neither is a terminal the command refuses and tells you
to pass `--yes`. This keeps a non-interactive run from sending anything by
accident.

| Flag | Meaning |
|---|---|
| `--stdin` | read the message from stdin instead of arguments |
| `--yes` | skip the confirmation prompt and send immediately |

Declining does not delete the spooled copy; it prints the path so you can
review, edit, or retry later.

## What is sent

The message is passed through the same redaction pipeline as crash reports
(paths, emails, IPs, URLs, tokens, and every built-in detector match) before
it is stored or sent. The report also carries minimal build context:

| Field | Content |
|---|---|
| `schema` | `pleno-dlp.feedback/v1` |
| `fingerprint` | 16 hex chars of SHA-256 over the digit-normalized message and command |
| `version`, `commit` | build metadata |
| `goos`, `goarch`, `go_version` | platform and toolchain |
| `command` | `feedback` |
| `flags` | names of the flags you passed; never values |
| `message` | the redacted message |
| `created_at` | UTC, truncated to the minute |

Hostname, username, working directory, environment variables, positional
arguments other than the message, flag values, and scanned content are never
collected.

## Configuration

| Setting | Where | Default |
|---|---|---|
| Endpoint | `feedback_endpoint` in `<config>/pleno-dlp/telemetry.json`, or `PLENO_DLP_FEEDBACK_ENDPOINT` (wins) | `https://feedback.plenoai.com/v1/pleno-dlp` |
| Spool root | `PLENO_DLP_TELEMETRY_DIR` | `os.UserConfigDir()/pleno-dlp` |

The endpoint must be `https`; plain `http` is accepted only for loopback
hosts. Point it at your own relay to keep feedback inside your organization.
Feedback does not require `pleno-dlp telemetry enable`: enabling crash
telemetry is consent for crashes, not for feedback.
