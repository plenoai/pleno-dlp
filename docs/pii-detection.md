# PII detection

PII scanning is opt-in. `pleno-dlp` can spawn a loopback-local engine for
the duration of a scan and label the resulting findings as PII.

## Quick start

Enable PII detection during a scan:

```sh
pleno-dlp scan filesystem ./src --pii-engine=anonymize
```

PII findings are emitted alongside secret findings and use the same output
formats (`table`, `json`, `sarif`) and
[gating controls](output-and-gating.md).

## Engine choices

### `anonymize`

This is the recommended default.

- Japanese-first NER plus regex-based detection
- Faster cold start than the privacy-filter path

```sh
pleno-dlp scan filesystem ./src --pii-engine=anonymize
pleno-dlp scan filesystem ./src --pii-engine=anonymize --pii-engine-language=ja
```

### `openai-pf`

- Uses a longer default readiness window on cold start

```sh
pleno-dlp scan filesystem ./src --pii-engine=openai-pf
pleno-dlp scan filesystem ./src --pii-engine=openai-pf --pii-engine-device=cuda
```

## Runtime requirements

Both engine paths require:

- `uv`
- Python 3.12+
- `git` when the engine source is a `git+...` checkout

The scan continues without PII detection if the engine fails to become ready
within the configured timeout.

## Shared scan flags

These flags live on `pleno-dlp scan`:

| Flag | Default | Meaning |
|---|---|---|
| `--pii-engine` | `off` | `off`, `anonymize`, or `openai-pf` |
| `--pii-engine-cmd` | engine-specific | command template used to spawn the selected engine |
| `--pii-engine-port` | `0` | auto-allocate a loopback port |
| `--pii-engine-ready-timeout` | `0` | engine default: 60s for `anonymize`, 300s for `openai-pf` |
| `--pii-engine-request-timeout` | `10s` | per `/api/analyze` request timeout |

Engine-specific flags:

| Flag | Applies to | Meaning |
|---|---|---|
| `--pii-engine-language` | `anonymize` | `ja`, `en`, or `auto` |
| `--pii-engine-device` | `openai-pf` | `auto`, `cpu`, `cuda`, or `mps` |

The CLI itself lists the current flags:

- `pleno-dlp scan --help`
- `pleno-dlp scan filesystem --help`

## Direct server commands

Typical usage is indirect through `pleno-dlp scan`, but both engines can be
started directly for local debugging.

### `pii-server`

```sh
pleno-dlp pii-server --port 8080
pleno-dlp pii-server --git-ref v0.1.0
pleno-dlp pii-server --no-fetch
```

Useful flags:

- `--source /path/to/checkout` to use an existing local checkout
- `--cache-dir ...` to control the cached clone / virtualenv location
- `--host ...` for loopback / private-network binds only

### `openai-pf-server`

The privacy-filter wrapper is documented separately:

- [`python/openaipf-server/README.md`](../python/openaipf-server/README.md)

## Safety model

- Engine processes bind only to loopback / private-network addresses
- Public bind targets such as `0.0.0.0` are refused

## Trust chain (server bootstrap)

`pii-server` and `openai-pf-server` each materialize a Python component on
first use via `git`/`uvx` fetch. Each fetched artifact is pinned and verified
as follows:

| Artifact | Pin | Verification | Failure mode |
|---|---|---|---|
| `pleno-anonymize` checkout (`pii-server --source`, default `git+https://github.com/plenoai/pleno-anonymize.git`) | `--git-ref` defaults to a release tag baked into the binary (`defaultPIIServerGitRef` in `cmd/pleno-dlp/cmd/pii_server.go`) | None beyond HTTPS transport integrity | Checking out the wrong ref surfaces as a `uv sync`/import failure |
| `python/openaipf-server` checkout (`openai-pf-server --source`, default `git+https://github.com/plenoai/pleno-dlp.git#subdirectory=python/openaipf-server`) | `--git-ref` defaults to a release tag baked into the binary (`defaultOpenAIPFGitRef` in `cmd/pleno-dlp/cmd/openai_pf_server.go`) | HTTPS transport integrity plus the fixed tag, nothing further | A wrong ref fails at `uv sync`/import |
| NER model wheels (spaCy `en_core_web_sm`, `pleno_anonymize_ja`, `pleno_anonymize_en`) | URL is a specific, versioned filename per wheel (`nerWheels` in `cmd/pleno-dlp/cmd/pii_server.go`) | pleno-dlp downloads each wheel itself (uv never fetches it directly), computes its sha256, and compares against a hash baked into the binary | A hash mismatch aborts `pii-server` setup before installation |

What this does **not** cover:

- The pinned tags' *own* supply chain (their dependencies, their CI).
The `pleno_anonymize_ja`/`pleno_anonymize_en` wheels are hosted on the
org-controlled Hugging Face organization (`huggingface.co/plenoai/...`).
