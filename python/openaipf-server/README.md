# openaipf-server

Loopback HTTP wrapper around [openai/privacy-filter](https://github.com/openai/privacy-filter)
for use by `pleno-dlp`.

This package is not on PyPI. `pleno-dlp openai-pf-server` materializes it
on first use via `uv tool run` (`uvx`). See ADR-0004 in the pleno-dlp
repo for the design rationale.

## Endpoints

- `GET /health` — liveness, always 200 once the process is up.
- `GET /ready` — 200 only after the opf model has loaded and a warmup
  forward pass has completed. The Go supervisor polls this; cold-path
  budget is 300s by default.
- `POST /api/analyze` — body `{"text": "..."}` returns
  `[{"entity_type": "private_emails", "bioes_tag": "E-private_emails",
  "start": 12, "end": 29, "score": 0.97, "text": "a@b.com"}, ...]`.

## Direct invocation

```
python -m openaipf_server --host 127.0.0.1 --port 8080 --device auto
```

`--host` is restricted to loopback / RFC1918 / link-local addresses.
Binding `0.0.0.0` or a public IP exits non-zero — pleno-dlp is a DLP
tool and must not relay scanned text to a public listener.
