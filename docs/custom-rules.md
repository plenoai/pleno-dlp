# Custom rules

`pleno-dlp scan … --rules rules.json` loads a JSON array of rules
(`pkg/detectors/custom`). Unknown fields are rejected.

| Field | Purpose |
|---|---|
| `name`, `keywords`, `regex` | Required. Keywords gate the regex per chunk. |
| `entropy_min`, `severity`, `description`, `help_uri` | Optional metadata and filtering. |
| `checksum` | Offline check-digit validation; failing candidates are dropped. |
| `validation` | Templated HTTPS liveness check with SSRF guards. |
| `verify_url`, `verify_header` | Legacy GET check; mutually exclusive with `validation`. |

## Checksum

```json
"checksum": {"algorithm": "crc32_base62", "body_group": "body", "checksum_group": "crc", "length": 6}
```

- `luhn`, `iban`: the body (`body_group`, or the whole match) must pass.
- `crc32_base62` (alphabet `0-9A-Za-z`), `crc32_hex`, `crc32_dec`: CRC32-IEEE
  of the body, rendered, zero-padded and truncated to the last `length`
  characters, must equal `checksum_group`.

A missing capture fails closed. Results carry `ExtraData["checksum"]="valid"`.

## Validation

```json
"validation": {
  "method": "POST",
  "url": "https://api.acme.example/v1/introspect?key={{ .Secret }}",
  "headers": {"Authorization": "Bearer {{ .Group.token }}"},
  "body": "{\"token\":\"{{ .Secret }}\"}",
  "success_status": [200],
  "failure_status": [401, 403],
  "success_body_contains": "\"active\":true",
  "allow_private_network": false
}
```

Only `{{ .Secret }}` and `{{ .Group.<named capture> }}` are accepted.
Defaults: `GET`, success `[200]`, failure `[401, 403]`. A failure status or a
success status whose body lacks `success_body_contains` reports
unverified; any other status is a verification error.

SSRF guards:

- The URL must be `https`. Placeholders are rejected in the scheme, userinfo,
  host and port, and substituted URL values are percent-escaped.
- Header names cannot be templated, `Host` cannot be set, and rendered
  header values cannot contain CR/LF.
- Each connection is checked after DNS resolution. Loopback, RFC 1918,
  link-local (including `169.254.169.254`), CGNAT, multicast and unspecified
  addresses are refused unless `allow_private_network` is true. Environment
  proxies are ignored so the guard sees the real address.
- Redirects are never followed. Response bodies are capped at 64 KiB, and
  each request times out after 10 s.
