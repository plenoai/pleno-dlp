# Feedback

`pleno-dlp feedback` sends a short, redacted message to the maintainers. It
is user-initiated and never runs on its own: nothing leaves the machine until
you confirm at the terminal, or pass `--yes` in a script you control.
Feedback ignores the crash opt-in and is locally limited to five upload
attempts per hour, shared across invocations. A throttled report is still
saved locally. See [Local throttling](telemetry.md#local-throttling).

```sh
pleno-dlp feedback "scan of a 2 GB monorepo OOMs"
echo "docs typo in verify-coverage.md" | pleno-dlp feedback --stdin
echo "please add a Jira label filter" | pleno-dlp feedback --yes
pleno-dlp scan --format json filesystem . > findings.json
# Replace HASH with the selected result's 64-character hash from findings.json.
pleno-dlp feedback --kind false-positive --scan-file .env --detector AWS \
  --finding-hash HASH "fixture value is not a credential"
```

False-positive mode rescans the named regular file offline with the selected
built-in secret detector. Copy `secret_hash` or `secret_hash_v2` from the
matching record in scan JSON as `--finding-hash`; the command reruns only the
selected detector and derives the redacted display from its result. It does
not import JSON or accept a caller-supplied redacted string. If a hash maps to
more than one distinct result, the command refuses to send. It previews the
detector, redacted match, and hashes before asking for confirmation. The file
is limited to 64 MiB and its contents and path remain local.

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
| `--kind` | choose `feedback` (default) or `false-positive` |
| `--scan-file` | local file to rescan offline for a false-positive report |
| `--detector` | detector name to run against `--scan-file` |
| `--finding-hash` | 64-character `secret_hash` or `secret_hash_v2` from scan JSON |

With no message argument, the command reads stdin automatically; `--stdin`
also requests this explicitly. `-y` is an alias for `--yes`.

Declining does not delete the spooled copy; it prints the path so you can
review, edit, or retry later.

## What is sent

The message and selected redacted match are passed through the same redaction
pipeline as crash reports (paths, emails, IPs, URLs, tokens, and built-in
detector matches) before they are stored or sent. Ordinary feedback uses
schema v1. False-positive reports use schema v2 and include the detector's
safe display and SHA-256 hashes of `Raw` and, when present, `RawV2`. The raw
bytes are used in memory only for `SafeRedacted` validation and hashing; they
are never serialized. The report also carries minimal build context:

| Field | Content |
|---|---|
| `schema` | `pleno-dlp.feedback/v1` or `/v2` for false-positive reports |
| `fingerprint` | 16 hex chars of SHA-256 over the digit-normalized message and command; v2 also includes detector and raw hashes |
| `version`, `commit` | build metadata |
| `goos`, `goarch`, `go_version` | platform and toolchain |
| `command` | `feedback` |
| `flags` | names of the flags you passed; never values |
| `message` | the redacted message |
| `created_at` | UTC, truncated to the minute |
| `match` (v2 only) | detector, safe `redacted` display, and `raw_hash` / optional `raw_v2_hash` |

Hostname, username, working directory, environment variables, positional
arguments other than the message, flag values, complete scanned-file contents,
source paths, and unselected findings are never collected. False-positive
reports include only the selected safe match fields above.

## Configuration

| Setting | Where | Default |
|---|---|---|
| Endpoint | `feedback_endpoint` in `<config>/pleno-dlp/telemetry.json`, or `PLENO_DLP_FEEDBACK_ENDPOINT` (wins) | `https://feedback.plenoai.com/v1/pleno-dlp` |
| Spool root | `PLENO_DLP_TELEMETRY_DIR` | `os.UserConfigDir()/pleno-dlp` |

The endpoint must be `https`; plain `http` is accepted only for loopback
hosts. Point it at your own relay to keep feedback inside your organization.
Feedback does not require `pleno-dlp telemetry enable`: enabling crash
telemetry is consent for crashes, not for feedback.
