# Go and x/net refresh — 2026-10-27

This change updates the supplied main snapshot directly. No code or module
files were adopted from Devin PRs #446, #447, #448, #450, #452, or #453.

## Version selection and advisory coverage

The [Go release policy and history](https://go.dev/doc/devel/release)
support the two latest major lines, currently 1.26 and 1.27. Their current
patches are 1.26.10 and 1.27.3. Select **Go 1.27.3** in `go.mod`; existing
CI and release workflows obtain their toolchain from that file.

Go 1.27.3 includes the [October 8 security fixes](https://groups.google.com/g/golang-dev/c/DaXYwdKVkRA)
for HTTP/2, CONNECT handling, Range headers, TLS ECH, template escaping,
MIME header limits, Windows rooted paths, and toolchain checksum checks.
It also covers [GO-2026-6809 / CVE-2026-111943](https://pkg.go.dev/vuln/GO-2026-6809),
the crypto/x509 intermediate-certificate distrust added in 1.27.3 and
1.26.10. Moving to 1.27.2 would lose that fix already present in the
snapshot's Go 1.26.10 requirement.

Select **golang.org/x/net v0.61.0**, the latest
[upstream tag](https://go.googlesource.com/net/+refs).
The [October 8 upstream announcement](https://groups.google.com/g/golang-dev/c/yWB4rz3eHjE)
identifies fixes shipped in v0.60.0 for CVE-2026-78659 (trailer memory),
CVE-2026-78669 (SETTINGS CPU), CVE-2026-78663 (flow control), and
CVE-2026-97032 (HPACK race); v0.61.0 retains these fixes. Earlier fixes
include [GO-2026-5026](https://pkg.go.dev/vuln/GO-2026-5026) (IDNA) and
[GO-2026-5942](https://pkg.go.dev/vuln/GO-2026-5942) (DNS records).
This source review does not establish application reachability or replace
a successful vulnerability scan.

The [v0.61.0 module requirements](https://raw.githubusercontent.com/golang/net/v0.61.0/go.mod)
raise x/crypto to v0.58.0, x/sys to v0.49.0, x/term to v0.47.0, and x/text
to v0.43.0. [x/text requires x/sync v0.24.0](https://raw.githubusercontent.com/golang/text/v0.43.0/go.mod).
These requirements are reflected in `go.mod`. Hashes were transcribed from
the [official x/net release commit](https://go.googlesource.com/net/+/c1d31df183e51b1075a2fd670d6f6f4efb871773%5E%21/)
and [official Go benchmarks go.sum](https://go.googlesource.com/benchmarks/+/refs/heads/master/go.sum).
They have not been locally verified against downloaded module contents.

The existing CI exception for [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932)
is unchanged: upstream still reports no fixed version for x/crypto/openpgp.

## Validation status

Passed: Go formatting, repository CI policy tests (standard-library-only,
using the installed Go 1.22.2 with module mode disabled), and all 10 Node
crash-relay tests.

Attempted but blocked by HTTP 403 download failures: `go mod tidy`,
`go mod verify`, govulncheck v1.1.4, staticcheck 2025.1.1, vet, build,
the full race gate, connector boundary test, CLI E2E, crash schema test,
detector-unit tests, and `make opf-native-test`.

The module graph has therefore **not** been regenerated or validated by
Go. Before merging, use a runner with Go 1.27.3 and trusted module access
to run `go mod tidy` and `go mod verify`, review any resulting module-file
diff, then run the checks in `.github/workflows/test.yml`, including
govulncheck. Do not treat this change as vulnerability-scan clean until
those gates pass.
