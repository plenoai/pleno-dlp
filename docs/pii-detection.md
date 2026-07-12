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

### `openai-pf-native`

The same privacy-filter model, run in-process through a statically linked
GGML runtime. Only present in `opf_native` builds (release assets named
`pleno-dlp-opf-native_<os>_<arch>`); selecting it in a default build exits
with instructions for obtaining a native binary.

- Select with `--pii-engine=openai-pf-native`
- No Python, `uv`, or subprocess involved
- Downloads the sha256-pinned GGUF weights on first use
  (override with `--pii-model-path`)
- Findings carry `extra_data.engine_impl="native"`; `pii_kind` values are
  identical to the `openai-pf` path

```sh
pleno-dlp scan filesystem ./src --pii-engine=openai-pf-native
pleno-dlp scan stdin --pii-engine=openai-pf-native --pii-model-path ./privacy-filter-f16.gguf
```

For `openai-pf-native`, `extra_data.start`/`extra_data.end` are UTF-8 byte
offsets relative to the scanned chunk. The subprocess `openai-pf` wrapper
keeps its character offsets; `anonymize` does not emit offsets.

## Runtime requirements

The subprocess engine paths (`anonymize`, `openai-pf`) require:

- `uv`
- Python 3.12+
- `git` when the engine source is a `git+...` checkout

`openai-pf-native` requires none of these.

The scan continues without PII detection if the engine fails to become ready
within the configured timeout.

## Shared scan flags

These flags live on `pleno-dlp scan`:

| Flag | Default | Meaning |
|---|---|---|
| `--pii-engine` | `off` | `off`, `anonymize`, `openai-pf`, or `openai-pf-native` |
| `--pii-engine-cmd` | engine-specific | command template used to spawn the selected engine |
| `--pii-engine-port` | `0` | auto-allocate a loopback port |
| `--pii-engine-ready-timeout` | `0` | engine default: 60s for `anonymize`, 300s for `openai-pf` |
| `--pii-engine-request-timeout` | `10s` | per `/api/analyze` request timeout |

Engine-specific flags:

| Flag | Applies to | Meaning |
|---|---|---|
| `--pii-engine-language` | `anonymize` | `ja`, `en`, or `auto` |
| `--pii-engine-device` | `openai-pf`, `openai-pf-native` | `auto`, `cpu`, `cuda`, or `mps` |
| `--pii-model` | `openai-pf-native` | GGUF variant: `q8` (default) or `f16` |
| `--pii-model-path` | `openai-pf-native` | local GGUF path, skips download and checksum pin |

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
- PII detection is mutually exclusive: choose one engine with `--pii-engine`

## Trust chain (server bootstrap)

`pii-server` and `openai-pf-server` each materialize a Python component on
first use via `git`/`uvx` fetch. Every checkout and artifact that crosses the
trust boundary before any of that code executes is handled as follows:

| Artifact | Pin | Verification | Failure mode |
|---|---|---|---|
| `pleno-anonymize` checkout (`pii-server --source`, default `git+https://github.com/plenoai/pleno-anonymize.git`) | `--git-ref` defaults to a release tag baked into the binary (`defaultPIIServerGitRef` in `cmd/pleno-dlp/cmd/pii_server.go`), not the mutable default branch | None beyond git's own transport integrity (HTTPS) — the ref itself is a fixed tag, so "what code runs" is reproducible across runs unless the operator opts out | Checking out the wrong ref surfaces as a `uv sync`/import failure, not a silent substitution |
| `python/openaipf-server` checkout (`openai-pf-server --source`, default `git+https://github.com/plenoai/pleno-dlp.git#subdirectory=python/openaipf-server`) | `--git-ref` defaults to a release tag baked into the binary (`defaultOpenAIPFGitRef` in `cmd/pleno-dlp/cmd/openai_pf_server.go`), not the mutable default branch | Same as above — HTTPS transport integrity plus a fixed tag | Same as above |
| NER model wheels (spaCy `en_core_web_sm`, `pleno_anonymize_ja`, `pleno_anonymize_en`) | URL is a specific, versioned filename per wheel (`nerWheels` in `cmd/pleno-dlp/cmd/pii_server.go`) | pleno-dlp downloads each wheel itself (uv never fetches it directly), computes its sha256, and compares against a hash baked into the binary | **Fail closed**: a hash mismatch aborts `pii-server` setup with an explicit `sha256 mismatch ... aborting pii-server setup` error before `uv pip install` ever sees the file. Covered by `TestDownloadAndVerifyWheel_HashMismatch` and `TestRunUVPipInstallNERWheels_AbortsOnHashMismatch` in `cmd/pleno-dlp/cmd/pii_server_test.go`. |

What this does **not** cover:

- The pinned tags' *own* supply chain (their dependencies, their CI) —
  pinning a ref bounds "which commit," not "is that commit's content
  trustworthy." That trust is inherited from the `plenoai` org. For
  `openai-pf-server` this is lower severity than the `pii-server` case
  (issue #248): the pin points at pleno-dlp's own repo, not a third party.
- Operators who explicitly pass `--git-ref ""` or `--git-ref main` (or any
  other ref) to either subcommand are consciously opting out of the pin;
  this is intentionally still possible for maintainers who need to test
  against tip, but it is not the shipped default and should not be used
  unattended/in CI.
The `pleno_anonymize_ja`/`pleno_anonymize_en` wheels are hosted on the
org-controlled Hugging Face organization (`huggingface.co/plenoai/...`,
relocated from a personal account on 2026-07-07, closing the #248
follow-up). The sha256 pins were verified unchanged across the move.

## Related docs

- [`docs/output-and-gating.md`](output-and-gating.md)
- [`python/openaipf-server/README.md`](../python/openaipf-server/README.md)
