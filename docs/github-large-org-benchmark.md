# GitHub selected-defaults large-org benchmark

This benchmark runs the GitHub connector at its repository-history
defaults: forks and archived repositories included, optional REST/wiki/gist/
artifact surfaces disabled, and `--repo-concurrency=1`.

## Reproduce

```sh
bench/github-large-org.sh
```

The harness builds 128 local Git repositories with two commits and two known
secret-bearing history chunks each, exposes them through 100+28-item mock
GitHub org API pages,
then runs the clone/history connector. It records wall time inside the
scan, peak process RSS from `getrusage` (Go compilation excluded), the
bytes present in each completed clone before cleanup, and the findings
the detector engine emits with network verification off.

## Result

Measured 2026-07-10 on Apple M3, macOS 26.3, Go 1.25.12, darwin/arm64:

| Repositories | Wall time | Peak RSS | Actual clone bytes | API calls | Findings |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 128 | 4,378 ms | 46,579,712 bytes | 3,477,020 bytes | 2 | 256 |

Because the org API is mocked and the repositories live on local disk,
these numbers say nothing about production GitHub network throughput.
