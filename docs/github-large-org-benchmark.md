# GitHub selected-defaults large-org benchmark

This deterministic benchmark exercises the default GitHub repository-history
surface: forks and archived repositories included, optional REST/wiki/gist/
artifact surfaces disabled, and `--repo-concurrency=1`.

## Reproduce

```sh
GOCACHE=/tmp/pleno-go-cache bench/github-large-org.sh
```

The harness builds 128 local Git repositories with two commits and two known
secret-bearing history chunks each, exposes them through 100+28-item mock
GitHub org API pages,
then runs the real clone/history connector. It records:

- wall time inside the scan;
- peak process RSS from `getrusage`, excluding Go compilation;
- actual bytes present in every completed clone before cleanup;
- mock API request count;
- findings emitted by the real detector engine with network verification off.

## Result

Measured 2026-07-10 on Apple M3, macOS 26.3, Go 1.25.12, darwin/arm64:

| Repositories | Wall time | Peak RSS | Actual clone bytes | API calls | Findings |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 128 | 4,378 ms | 46,579,712 bytes | 3,477,020 bytes | 2 | 256 |

The fixture is intentionally local and deterministic. It measures lifecycle,
clone, state, and Git-history overhead without Internet variance; it is not a
claim about production GitHub network throughput.
