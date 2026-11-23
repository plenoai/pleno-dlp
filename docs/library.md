# Embeddable library API

pleno-dlp is a CLI first, but its scanner is also available as a library for
Go, Python, and Node.js. All three languages share one contract, defined by
the Go package [`pkg/dlp`](../pkg/dlp/dlp.go).

## Stability

`pkg/dlp` is the only package with a compatibility promise. Every other
package under `pkg/` is internal and may change in any release.

| Surface | Promise |
|---|---|
| Exported identifiers in `pkg/dlp` | Not removed or changed incompatibly within a major `APIVersion` |
| JSON field names of `Finding`, `ScanOptions`, `VerifyResult`, `RevokeOptions`, `RevokeResult`, `Detector` | Frozen by `TestJSONContractFrozen`; new optional fields may be added |
| C ABI symbols in `cmd/libpleno-dlp` | Same as `pkg/dlp` |
| Error codes | `unknown_detector`, `not_supported`, `not_confirmed`, `invalid_argument`, `internal` |
| Detector names and their findings | Not frozen; detectors are added and tuned in minor releases |

`dlp.APIVersion` (currently `1.0.0`) is versioned separately from the CLI.
Its major component changes only on a breaking change to the surfaces above.

## Operations

| Operation | Go | Python | Node.js | Network |
|---|---|---|---|---|
| Scan a buffer | `dlp.ScanBytes` | `scan_bytes` | `scanBytes` | Only with `Verify` |
| Scan files and directories | `dlp.ScanPaths` | `scan_paths` | `scanPaths` | Only with `Verify` |
| Verify one secret | `dlp.Verify` | `verify` | `verify` | Always |
| Revoke one secret | `dlp.Revoke` | `revoke` | `revoke` | With `Confirm` |
| List detectors | `dlp.Detectors` | `detectors` | `detectors` | Never |

## Safety defaults

The library keeps the CLI's safety rules:

- **Scans are offline.** No candidate leaves the process unless the caller
  sets `Verify`.
- **Findings are redacted.** `Finding.Raw` and `Finding.RawV2` stay empty
  unless the caller sets `IncludeRaw`. `Finding.Redacted` never contains the
  complete secret.
- **Revoke requires intent.** `Revoke` returns `ErrNotConfirmed`
  (`not_confirmed`) unless exactly one of `Confirm` or `DryRun` is set.
  `DryRun` checks the detector name and capability without a provider call.
  The library does not read `PLENO_DLP_ALLOW_REVOKE`; that gate belongs to
  the CLI (see [revoke-support.md](revoke-support.md)). Embedding programs
  own their own authorization policy.

## Go

```go
import "github.com/plenoai/pleno-dlp/pkg/dlp"

findings, err := dlp.ScanBytes(ctx, data, dlp.ScanOptions{})
for _, f := range findings {
	fmt.Println(f.Detector, f.Redacted, f.Verdict)
}
```

Importing `pkg/dlp` registers the full built-in detector set.

## Python

```sh
pip install pleno-dlp
```

```python
import pleno_dlp

for f in pleno_dlp.scan_paths("src/"):
    print(f.detector, f.path, f.line, f.redacted)

pleno_dlp.revoke("GitHub", token, dry_run=True)
```

Errors raise `pleno_dlp.PlenoDLPError` with a `code` attribute.

## Node.js

```sh
npm install pleno-dlp
```

```js
import { scanBytes, PlenoDLPError } from 'pleno-dlp';

for (const f of scanBytes(process.env.SOME_BLOB ?? '')) {
  console.log(f.detector, f.redacted);
}
```

TypeScript declarations ship in the package. Errors throw `PlenoDLPError`
with a `code` property.

Calls are synchronous: they block the calling thread until the scan
finishes. Run large scans in a worker thread (Node.js) or thread pool
(Python).

## Platforms

Published packages bundle the shared library for:

| OS | Architecture | Python wheel tag |
|---|---|---|
| Linux (glibc) | arm64 | `manylinux_2_X_aarch64` |
| Linux (glibc) | x86-64 | `manylinux_2_X_x86_64` |
| macOS 11+ | arm64 | `macosx_11_0_arm64` |
| macOS 11+ | x86-64 | `macosx_11_0_x86_64` |
| Windows | x86-64 | `win_amd64` |
| Windows | arm64 | `win_arm64` |

`X` is the newest glibc symbol version the library needs, measured at
build time. macOS and Windows libraries are cross-linked with `zig cc` on
Linux; darwin links against the symbol stubs in `scripts/darwin-stubs`
(regenerate them with `scripts/bindings.sh darwin-stubs <native dylib>`
when a Go upgrade breaks the link). On other platforms (musl, 32-bit), build the library yourself and point the
binding at it:

```sh
scripts/bindings.sh lib ./out          # needs Go and a C compiler
export PLENO_DLP_LIBRARY=$PWD/out/libpleno_dlp.dylib
```

[ADR 0001](adr/0001-language-bindings.md) explains the binding design.

## C ABI

Build with `scripts/bindings.sh lib <dir>`. Each function takes
NUL-terminated UTF-8 strings and returns a JSON envelope, either
`{"ok": <value>}` or `{"error": {"code": "...", "message": "..."}}`. Release
every returned pointer with `pleno_dlp_free`.

| Symbol | Arguments |
|---|---|
| `pleno_dlp_version()` | — |
| `pleno_dlp_detectors()` | — |
| `pleno_dlp_scan_bytes(data, len, opts_json)` | buffer, byte length, `ScanOptions` JSON |
| `pleno_dlp_scan_paths(paths_json, opts_json)` | JSON array of paths, `ScanOptions` JSON |
| `pleno_dlp_verify(detector, secret)` | — |
| `pleno_dlp_revoke(detector, secret, opts_json)` | `RevokeOptions` JSON |
| `pleno_dlp_free(ptr)` | pointer returned by any function above |

## Releases

A `vX.Y.Z` tag push runs `.github/workflows/release.yml`. After the GitHub
release is published, the `pypi` and `npm` jobs publish the bindings with
the same version through OIDC trusted publishing. The repository stores no
registry tokens. One-time registry setup:

- **PyPI:** add a trusted publisher for project `pleno-dlp`: owner
  `plenoai`, repository `pleno-dlp`, workflow `release.yml`, environment
  `pypi`.
- **npm:** add a trusted publisher for `pleno-dlp`: repository
  `plenoai/pleno-dlp`, workflow `release.yml`, environment `npm`. Leave
  direct publishing disabled: CI runs `npm stage publish`, and a maintainer
  approves each version with 2FA (`npm stage list pleno-dlp`, then
  `npm stage approve <stage-id>`, or the npmjs.com UI) before it is public.
