# Alert webhooks

`pleno-dlp scan … --alert-webhook URL` POSTs a summary of findings to each
webhook after the scan completes, when at least one finding meets
`--alert-min-severity`.

| Flag | Default | Notes |
|---|---|---|
| `--alert-webhook URL` | none, repeatable | HTTPS only (plain HTTP is allowed for loopback). |
| `--alert-min-severity` | `medium` | `info`, `low`, `medium`, `high`, `critical`. |
| `--alert-dry-run` | off | Print each payload to stderr instead of POSTing it. |

The payload shape follows the host:

| Host | Payload |
|---|---|
| `slack.com`, `*.slack.com` | Slack `{"text": …}` |
| `*.office.com`, `webhook.office.*`, `*.logic.azure.com` | Teams Adaptive Card message |
| anything else | generic JSON (`tool`, `version`, `source`, `min_severity`, `total`, `by_severity`, `findings[]`) |

Security properties:

- Payloads carry the detector's display-safe redaction, location, severity,
  and verdict. Raw secrets are never sent.
- Logs and errors print only the webhook scheme and host, because Slack and
  Teams embed the credential in the URL path.
- Redirects are not followed.
- Delivery retries twice with exponential backoff on network errors, 429,
  and 5xx. Other 4xx responses are not retried.
- Delivery is best-effort. A failure prints a warning and does not change the
  scan exit code.
- Chat payloads list at most 25 findings. Totals count all of them.
