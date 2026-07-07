# PII detection

PII scanning is opt-in. `pleno-dlp` can spawn a loopback-local engine for
the duration of a scan and label the resulting findings as PII.

## Quick start

Enable PII detection during a scan:

```sh
pleno-dlp scan filesystem ./src --pii-engine=anonymize
```

PII findings are emitted alongside secret findings and use the same output
formats (`table`, `json`, `sarif`) and gating controls.

## Engine choices

### `anonymize`

Recommended default for README-level usage.

- Japanese-first NER plus regex-based detection
- Faster cold start than the privacy-filter path
- Supports `--pii-engine-language=ja|en|auto`

```sh
pleno-dlp scan filesystem ./src --pii-engine=anonymize
pleno-dlp scan filesystem ./src --pii-engine=anonymize --pii-engine-language=ja
```

### `openai-pf`

Available for operators who need the privacy-filter model path.

- Select with `--pii-engine=openai-pf`
- Supports `--pii-engine-device=auto|cpu|cuda|mps`
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

Inspect the live CLI for the current flag surface:

- `pleno-dlp scan --help`
- `pleno-dlp scan filesystem --help`

## Direct server commands

Typical usage is indirect through `pleno-dlp scan`, but both engines can be
started directly for local debugging.

### `pii-server`

`pii-server` foreground-spawns the `pleno-anonymize` HTTP server via `uv`.

```sh
pleno-dlp pii-server --port 8080
pleno-dlp pii-server --git-ref v0.5.0
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
- PII detection is mutually exclusive: choose one engine with `--pii-engine`

## Trust chain (`pii-server` bootstrap)

`pii-server` materializes a third-party Python server on first use via `git`
clone + `uv`. Two artifact classes cross the trust boundary before any code
from them executes, and each is handled differently:

| Artifact | Pin | Verification | Failure mode |
|---|---|---|---|
| `pleno-anonymize` checkout (`--source`, default `git+https://github.com/plenoai/pleno-anonymize.git`) | `--git-ref` defaults to a release tag baked into the binary (`defaultPIIServerGitRef` in `cmd/pleno-dlp/cmd/pii_server.go`), not the mutable default branch | None beyond git's own transport integrity (HTTPS) — the ref itself is a fixed tag, so "what code runs" is reproducible across runs unless the operator opts out | Checking out the wrong ref surfaces as a `uv sync`/import failure, not a silent substitution |
| NER model wheels (spaCy `en_core_web_sm`, `pleno_anonymize_ja`, `pleno_anonymize_en`) | URL is a specific, versioned filename per wheel (`nerWheels` in `cmd/pleno-dlp/cmd/pii_server.go`) | pleno-dlp downloads each wheel itself (uv never fetches it directly), computes its sha256, and compares against a hash baked into the binary | **Fail closed**: a hash mismatch aborts `pii-server` setup with an explicit `sha256 mismatch ... aborting pii-server setup` error before `uv pip install` ever sees the file. Covered by `TestDownloadAndVerifyWheel_HashMismatch` and `TestRunUVPipInstallNERWheels_AbortsOnHashMismatch` in `cmd/pleno-dlp/cmd/pii_server_test.go`. |

What this does **not** cover:

- The pinned `pleno-anonymize` tag's *own* supply chain (its dependencies,
  its CI) — pinning a ref bounds "which commit," not "is that commit's
  content trustworthy." That trust is inherited from the `plenoai` org.
- Operators who explicitly pass `--git-ref ""` or `--git-ref main` (or any
  other ref) are consciously opting out of the pin; this is intentionally
  still possible for maintainers who need to test against tip, but it is
  not the shipped default and should not be used unattended/in CI.
- **Known follow-up**: the `pleno_anonymize_ja`/`pleno_anonymize_en` wheels
  are currently hosted on a personal Hugging Face account
  (`huggingface.co/0xhikae/...`) rather than an org-controlled one. Moving
  them requires HF org credentials that are not available to this change;
  the sha256 pin means a compromised or swapped file on that account still
  gets rejected, but the account itself remains a single point of trust
  until relocation. Tracked as a follow-up to issue #248 — the code is
  structured so relocating a wheel is a two-field edit (`url`, `sha256`) in
  the `nerWheels` table, not a redesign.

## Related docs

- [`docs/output-and-gating.md`](output-and-gating.md)
- [`python/openaipf-server/README.md`](../python/openaipf-server/README.md)
