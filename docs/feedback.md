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

Feedback defaults to `--pii-engine=auto`. It uses an engine that is already
active in the process, or starts a complete, pinned local cache in offline
mode. The anonymize cache must contain its pinned checkout, virtual
environment, and model packages; `uv` alone is not enough. Native
privacy-filter requires an `opf_native` build and an existing GGUF model.
Automatic selection does not fetch source or download models.
`--pii-engine=off` disables this pass. An
explicit `--pii-engine=anonymize` or `--pii-engine=openai-pf-native` uses the
selected engine's normal startup path and can install or download missing
runtime assets.

When no local engine is available, the command warns that names and other PII
may remain, then applies pattern and secret-detector redaction. If a selected
engine cannot start or fails while analyzing either the message or the chosen
match display, feedback stops before it writes a spool file or sends a report.
PII analysis runs locally; the report contains the redacted text only.
Each text field has a two-second PII-result acceptance deadline. This is not a
hard wall-clock limit: native synchronous inference cannot be interrupted in
the middle of a C call. If it returns after the deadline, its result is
rejected and feedback does not save or send the report.

## Local record

Every report is written to the spool before sending, so there is a local copy
whether the upload succeeds or not. Reports live under
`<telemetry root>/feedback/`. The spool uses the local feedback schema. The
built-in intake endpoint maps it to the separate `pleno-dlp.report/v1` or
`pleno-dlp.report/v2` envelope; a configured custom relay continues receiving
the local feedback schema directly.

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

Send this feedback report to https://intake.plenoai.com/v1/pleno-dlp? [y/N]
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
| `--pii-engine` | `auto` (default), `off`, `anonymize`, or `openai-pf-native` |
| `--pii-engine-cmd` | anonymize command used when that engine is explicitly selected |
| `--pii-engine-port` | loopback port for anonymize (`0` chooses one automatically) |
| `--pii-engine-language` | anonymize language hint: `ja`, `en`, or `auto` |
| `--pii-engine-ready-timeout` | maximum startup wait (`0` uses 60 seconds) |
| `--pii-engine-request-timeout` | per-request timeout for anonymize; feedback rejects results returned after two seconds per field, though synchronous inference may continue |
| `--pii-engine-device` | native inference device: `auto`, `cpu`, `cuda`, or `mps` |
| `--pii-model` | native GGUF variant: `q8` or `f16` |
| `--pii-model-path` | local native GGUF path |

With no message argument, the command reads stdin automatically; `--stdin`
also requests this explicitly. `-y` is an alias for `--yes`.

Declining does not delete the spooled copy; it prints the path so you can
review, edit, or retry later.

## What is sent

The message and selected redacted match are analyzed by the optional local
PII engine before pattern redaction removes context, then passed through
pattern and secret-detector redaction before storage or sending. The local
spool uses
`pleno-dlp.feedback/v1` for ordinary feedback and `/v2` for false-positive
reports. The built-in intake maps those records to `pleno-dlp.report/v1` with
`kind=feedback`, or `/v2` with `kind=false-positive` and a nested match. A
custom relay receives the local feedback schema directly. False-positive
records include the detector's safe display and SHA-256 hashes of `Raw` and,
when present, `RawV2`. The raw bytes are used in memory only for `SafeRedacted`
validation and hashing; they are never serialized. The report also carries
minimal build context:

| Field | Content |
|---|---|
| `schema` (local spool/custom relay) | `pleno-dlp.feedback/v1` or `/v2` for false-positive reports |
| `schema`, `kind` (built-in intake) | `pleno-dlp.report/v1`, `feedback`; or `/v2`, `false-positive` |
| `fingerprint` | 16 hex chars of SHA-256 over the digit-normalized message and command; v2 also includes detector and raw hashes |
| `version`, `commit` | build metadata |
| `goos`, `goarch`, `go_version` | platform and toolchain |
| `command` | `feedback` |
| `flags` | names of the flags you passed; never values |
| `message` | the redacted message |
| `created_at` | UTC, truncated to the minute in the local spool and custom-relay payload |
| `match` (v2 only) | detector, safe `redacted` display, and `raw_hash` / optional `raw_v2_hash` |

Hostname, username, working directory, environment variables, positional
arguments other than the message, flag values, complete scanned-file contents,
source paths, and unselected findings are never collected. False-positive
reports include only the selected safe match fields above.

## Redaction cost

The `BenchmarkFeedbackRedaction` benchmark compares patterns only with all
registered detectors, measuring the current secret-detector pass against its
two-second budget:

```sh
go test ./pkg/telemetry/crash -run '^$' -bench '^BenchmarkFeedbackRedaction$' -benchtime=5x -count=3
```

On an Apple M3 with `GOMAXPROCS=2`, three runs of five iterations measured 615
registered detectors. The 69-byte input took 0.158–0.240 ms with all
detectors, compared with 0.031–0.034 ms for patterns only. The 31,744-byte
input took 17.75–18.51 ms with all detectors, compared with 6.18–8.68 ms for
patterns only. These benchmark runs completed below the all-detector budget;
they do not guarantee a worst-case bound or measure live PII model startup or
inference. The separate two-second PII-result acceptance deadline applies per
text field. A synchronous native inference call can continue past that
deadline, but its late result is rejected when the call returns.

## Configuration

| Setting | Where | Default |
|---|---|---|
| Endpoint | `feedback_endpoint` in `<config>/pleno-dlp/telemetry.json`, or `PLENO_DLP_FEEDBACK_ENDPOINT` (wins) | `https://intake.plenoai.com/v1/pleno-dlp` |
| Spool root | `PLENO_DLP_TELEMETRY_DIR` | `os.UserConfigDir()/pleno-dlp` |

The endpoint must be `https`; plain `http` is accepted only for loopback
hosts. Point it at your own relay to keep feedback inside your organization.
Feedback does not require `pleno-dlp telemetry enable`: enabling crash
telemetry is consent for crashes, not for feedback.
