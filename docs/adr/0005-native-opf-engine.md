# ADR 0005: In-process openai-pf engine via cgo (privacy-filter.cpp)

Status: accepted

## Context

The original openai/privacy-filter integration ran through a Python FastAPI
wrapper. That path has been removed; privacy-filter is now native-only.

`localai-org/privacy-filter.cpp` (MIT) runs the same model natively. The PoC
(`_workspace/poc-opfnative.md`) built `libpf.a` on macOS arm64 with cmake preset
`release`, and its flat C API (`pf_load`/`pf_classify`/`pf_free`/`pf_last_error`,
ABI v1) returned exact-offset PII spans with BIOES aggregation resolved inside
the library. This ADR is the design for wiring that into pleno-dlp as
`--pii-engine=openai-pf-native`, an **optional, in-process** engine, without
disturbing the default pure-Go release.

Hard constraints:
1. The default release (tag push → GoReleaser trusted publishing) stays a
   `CGO_ENABLED=0` pure-Go cross-compile. It must not break.
2. The native engine is opt-in behind build tag `opf_native`. A tag-free binary
   asked for `openai-pf-native` fails with a clear, install-directing error.
3. The independent `anonymize` engine remains available.
4. Single Go module; new packages under `pkg/<area>/<name>/`, no new `go.mod`.
5. PII findings set `ExtraData["finding_class"]="pii"`.

## Decision

### Shape: reuse the detector, add one build-tagged in-process engine

The engine is in-process, so it needs no subprocess/HTTP/`/ready`/port. It does
need a lifecycle object that `pf_load`s the GGUF once and `pf_free`s at scan
end. New package **`pkg/piiengine/opfnative`** (build tag `opf_native`) provides
it, mirroring the supervisor's handle surface (`New`/`Analyze`/`Close`/
`SetDefault`/`Default`).

The detector remains `pkg/detectors/openaipf`, `DetectorType=PIIOpenAIPF`.
Native findings carry `ExtraData["engine"]="openai-pf-native"`.

### A. C sources: pinned-commit fetch, SHA-verified, git-ignored

A committed lockfile `pkg/piiengine/opfnative/deps.lock` pins pf.cpp (repo +
commit) and its ggml submodule commit. A committed fetch script
(`scripts/opf-native/fetch-deps.sh`) clones pf.cpp at the pinned commit, inits
ggml at its pin, and **verifies both resolved SHAs against the lock, failing
closed on mismatch**. Sources land in git-ignored `build/opf-native/`.

Not vendored (would commit tens of MB of C/C++/Metal into a repo whose default
consumers never compile it) and not a submodule (would force `--recursive` on
every clone, including the pure-Go release and test workflows). Only an
`opf_native` build runs the fetch. The git commit SHA content-addresses the
whole tree — stronger integrity than a regenerable codeload tarball hash.

Pins (from PoC):

| artifact | pin |
|---|---|
| localai-org/privacy-filter.cpp | `735a6c28607ee82afc3a670383f41b55266a3b9a` |
| ggml submodule | `3af5f5760e19a96427f5f7a93b79cbdf3d4b265b` |

### B. Build: cmake → static `.a` → cgo via `${SRCDIR}/cdeps`

`cmake --preset release` (static) installs `libpf.a`, `libggml*.a`, and `pf.h`
into git-ignored `pkg/piiengine/opfnative/cdeps/{lib,include}`. cgo resolves
them with `${SRCDIR}/cdeps` (package-relative, CWD-independent).

Configure flags for portable release libs: `-DBUILD_SHARED_LIBS=OFF`,
`-DGGML_NATIVE=OFF`; darwin `-DGGML_METAL_EMBED_LIBRARY=ON`; linux
`-DGGML_OPENMP=OFF` and CPU-only (no CUDA).

Link flags, in per-OS build-tagged cgo files:

- `pkg/piiengine/opfnative/cgo_darwin.go` (`//go:build opf_native && darwin`):
  `#cgo LDFLAGS: -L${SRCDIR}/cdeps/lib -lpf -lggml -lggml-base -lggml-cpu -lggml-blas -lggml-metal -lc++ -framework Foundation -framework Metal -framework MetalKit -framework Accelerate -framework QuartzCore`
- `pkg/piiengine/opfnative/cgo_linux.go` (`//go:build opf_native && linux`):
  `#cgo LDFLAGS: -L${SRCDIR}/cdeps/lib -Wl,--start-group -lpf -lggml -lggml-base -lggml-cpu -Wl,--end-group -lstdc++ -lm -lpthread -ldl -static-libstdc++ -static-libgcc`
- `pkg/piiengine/opfnative/cgo.go` (`//go:build opf_native`):
  `#cgo CFLAGS: -I${SRCDIR}/cdeps/include`, the `import "C"` including `pf.h`,
  and the ABI-v1 marshalling wrappers.

The `-lggml*` set is deterministic per the pin; if upstream reorganizes ggml
targets, the list and this ADR change together.

Makefile targets (names are contract for CI/docs):

| target | does |
|---|---|
| `opf-native-deps` | run fetch-deps.sh (fetch + SHA-verify sources) |
| `opf-native-lib` | cmake configure+build; install `.a` + `pf.h` into `cdeps/` |
| `opf-native-build` | `CGO_ENABLED=1 go build -tags opf_native -o bin/pleno-dlp-opf ./cmd/pleno-dlp` (deps on `opf-native-lib`) |
| `opf-native-test` | tagged `go vet`, `staticcheck`, and full race suite |
| `opf-native-clean` | remove `build/opf-native/`, `cdeps/`, `bin/pleno-dlp-opf` |

### C. Release/CI: separate additive workflow

`.goreleaser.yaml` and `.github/workflows/release.yml` are **not touched**. A
new `.github/workflows/release-native.yml` triggers on the same `v*` tag and
attaches native binaries to the release GoReleaser creates. This isolates
constraint 1: a native build failure cannot break the signed/SBOM'd/attested
pure-Go release.

Matrix: `macos-14` (darwin/arm64), `ubuntu-latest` (linux/amd64),
`ubuntu-24.04-arm` (linux/arm64). Each job runs `make opf-native-build` and
`make opf-native-test`, packages
`pleno-dlp-opf-native_<os>_<arch>.tar.gz` (disjoint from GoReleaser's
`pleno-dlp_<os>_<arch>.tar.gz`), signs the archive with cosign, emits an SBOM,
and uploads GitHub build provenance after the signed GoReleaser workflow
succeeds. The archive includes `THIRD_PARTY_NOTICES` for the statically linked
MIT dependencies. All actions are pinned to full commit SHAs. Static linkage on linux
(`-static-libstdc++ -static-libgcc`) keeps the binary portable across glibc
hosts; the macOS binary requires Metal (every arm64 Mac).

Native `staticcheck`/`go vet`/`go test` run with `-tags opf_native` on the
native runners. The default `test.yml` stays tag-free and needs no cgo
toolchain.

### D. GGUF weights: runtime first-download, SHA-pinned, fail-closed

Weights (q8 1.5 GB / f16 2.6 GB) are not embedded. On first use the engine
downloads to `os.UserCacheDir()/pleno-dlp/models/privacy-filter-<variant>-<sha256[:8]>.gguf`,
atomically (`.tmp` → verify → rename) and lock-guarded. URL + sha256 are Go
consts in `pkg/piiengine/opfnative/models.go`:

| variant | sha256 |
|---|---|
| q8 (default) | `80efc1803eda7c095a79741d2008c07e2e0a57b01bac8825fbeb448fd097998c` |
| f16 | `eb71312b6b9370d0fe582e576b840567bb06603c4de241c6d899205d1b04dc81` |

Source: `LocalAI-io/privacy-filter-GGUF` (HuggingFace) — pin the revision in the
`resolve/<rev>/…` URL, not `main`. New flags `--pii-model` (`q8`|`f16`) and
`--pii-model-path` (explicit GGUF, bypassing download and checksum: a
user-supplied path is trusted). `--pii-engine-device` is reused
(`auto`→Metal/darwin, CPU/linux; `mps`→Metal). A **downloaded** file failing
its checksum is fatal: the artifact is deleted and a typed error returned —
inference never runs on unverified weights.

### E. Public API (`pkg/piiengine/opfnative`)

```
type Config struct { ModelPath, Device string; Threshold float64 } // Threshold default 0.5
type Engine struct{ /* holds C handle */ }
func New(Config) (*Engine, error)                       // pf_load
func (*Engine) Analyze(ctx context.Context, text string) ([]Finding, error) // pf_classify
func (*Engine) Close() error                            // pf_free
func SetDefault(*Engine); func Default() *Engine
type Finding struct { EntityType, BIOESTag string; Start, End int; Score float64; Text string }
```

`Finding.BIOESTag` is always empty because libpf resolves spans internally. An **untagged**
`doc.go` keeps the package valid under a tag-free `go build ./...`.

### F. Engine selection & the "not built" error

`--pii-engine=openai-pf-native` is accepted by `validPIIEngineMode` in **all**
builds and added to both "valid: …" error strings. `startPIIEngine` dispatches
`openai-pf-native` to `startOpenAIPFNative`, defined twice:

- `cmd/pleno-dlp/cmd/pii_engine_native_stub.go` (`//go:build !opf_native`):
  `const nativeOPFBuilt = false`, plus `errNativeNotBuilt` and a
  `startOpenAIPFNative` returning it.
- `cmd/pleno-dlp/cmd/pii_engine_native.go` (`//go:build opf_native`):
  `const nativeOPFBuilt = true`; resolves the model path (D), `New`s the
  `Engine`, `opfnative.SetDefault`s it,
  returns a stop func calling `Close`.

`scan.go` preflight (beside the existing `validPIIEngineMode` gate) hard-fails
when `openai-pf-native` is selected and `!nativeOPFBuilt`, returning
`errNativeNotBuilt` as a config error — so "not built" is not swallowed by the
spawn-failure "continue without PII" downgrade (constraint 2). Genuine native
runtime failures (download, `pf_load`) keep that downgrade, consistent with the
other engines.

`errNativeNotBuilt`:

```
--pii-engine=openai-pf-native requires a binary built with the 'opf_native'
build tag (in-process privacy-filter.cpp inference). This is the portable
pure-Go build, which does not include it. Get the native build: download
pleno-dlp-opf-native_<os>_<arch> from
https://github.com/plenoai/pleno-dlp/releases, or build locally with
`make opf-native-build`. See docs/adr/0005-native-opf-engine.md.
```

### verify-coverage impact: none

Native reuses `PIIOpenAIPF` (class b, unverified-by-design, `finding_class=pii`).
No new DetectorType, so the CI-enforced three-way sync
(`pkg/detectors/verifycoverage/verifycoverage.go` `Classes` ↔
`docs/verify-coverage.md` ↔ registration) is untouched.

## Consequences

- The default pure-Go release remains available without the native engine.
- Operators on native binaries get in-process opf with no Python/`uv`
  dependency and no per-chunk HTTP hop, at the cost of a cgo toolchain +
  cmake + a one-time C-dep build (cached in CI).
- Two release artifact families now exist. The native binaries are larger to
  build, are platform-restricted (darwin needs Metal; linux glibc), and are
  produced on native runners; the tag-free error keeps that invisible to
  pure-Go users who never opt in.
- Weights remain a runtime download; first native run on a cold cache pays the
  1.5 GB (q8) fetch. `--pii-model-path` lets air-gapped operators pre-place it.
