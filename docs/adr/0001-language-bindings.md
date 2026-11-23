# ADR 0001: Language bindings use a c-shared library

- Status: Accepted
- Date: 2026-11-23
- Issue: #816 (epic #817)

## Context

Issue #816 requires Python and Node.js packages over the scanner, with
scan, verify, and revoke operations. The two candidate mechanisms are a Go
`c-shared` library loaded through a foreign function interface (FFI), and a
WebAssembly (WASM) module.

## Decision

Build `cmd/libpleno-dlp` with `-buildmode=c-shared`. Load it with `ctypes`
in Python and `koffi` in Node.js. Exchange JSON across the boundary.

## Rationale

1. **Verify and revoke need the network.** Both operations make HTTPS
   calls to providers. `GOOS=wasip1` has no socket API in Go's standard
   library. `GOOS=js` sends HTTP through the host's `fetch`, which needs
   separate code paths per host and drops pleno-dlp's verification
   transport controls in `pkg/verify`. A native library runs the same
   `net/http` stack as the CLI.
2. **Filesystem scans need real paths.** `ScanPaths` walks directories with
   the CLI's excludes and size limits. WASI would need preopened
   directories for every root, which conflicts with arbitrary caller paths.
3. **Performance.** WASM builds of Go run single-threaded under most hosts
   and lose the engine's worker concurrency. The native library keeps it.
4. **No compiler at install time.** `ctypes` ships with CPython, and `koffi`
   ships prebuilt binaries. Users install a wheel or tarball and need no
   toolchain.
5. **One contract.** JSON over seven C functions keeps each binding small
   (about 200 lines) and lets `pkg/dlp` own every semantic rule. A
   per-language native module (pyo3-style or N-API) would duplicate type
   mapping in each language.

## Consequences

- Each target platform needs its own library build with a C toolchain.
  Release builds Linux arm64 natively and Linux x86-64 with a GNU cross
  compiler, both on the pinned Blacksmith arm64 pool
  (`tests/ci/self_hosted_runner_test.go`). macOS (arm64, x86-64) and
  Windows (x86-64, arm64) cross-link with a checksum-pinned `zig cc` on the
  same pool, so the runner policy stays unchanged (#853). Darwin links
  against text-based stubs (`scripts/darwin-stubs`) that export only the
  CoreFoundation/Security symbols the Go runtime imports, instead of the
  macOS SDK; a symbol a future Go release adds fails the link rather than
  shipping a broken library. The darwin builds were verified on a Mac
  (arm64 natively, x86-64 under Rosetta) before adoption. The Windows
  builds are executed on every release: `bindings-smoke-windows-{amd64,arm64}`
  install the wheel and the staged npm library on GitHub-hosted
  `windows-2025` / `windows-11-arm` and run both binding test suites, and
  `pypi`/`npm` depend on them (#879). This is the repository's only
  GitHub-hosted runner exception: Blacksmith offers no Windows pool and wine
  on the arm64 pool cannot run x86-64 PE images reliably; the jobs are
  read-only and hold no secrets or OIDC token.
- The Go runtime starts inside the host process. One process loads one
  copy of the runtime; repeated calls reuse it.
- Calls are synchronous. Async wrappers are left to callers (worker
  threads, thread pools) rather than added to the contract.
- The npm package bundles every platform library (about 14 MB each) instead of
  per-platform packages, so one trusted-publisher entry covers it.
- The library is AGPL-3.0-only, like the CLI. Embedding programs inherit
  those terms.
