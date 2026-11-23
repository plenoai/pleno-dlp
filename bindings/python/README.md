# pleno-dlp for Python

Python bindings for [pleno-dlp](https://github.com/plenoai/pleno-dlp), a
secret and PII scanner. Scan buffers and files, verify a secret with its
provider, and revoke leaked credentials.

```python
import pleno_dlp

for f in pleno_dlp.scan_bytes(open("config.env", "rb").read()):
    print(f.detector, f.redacted, f.verdict)
```

Scans are offline and findings are redacted unless you pass `verify=True` or
`include_raw=True`. `revoke()` requires `confirm=True` or `dry_run=True`.

See the [library documentation](https://github.com/plenoai/pleno-dlp/blob/main/docs/library.md)
for the full API, supported platforms, and stability policy.
