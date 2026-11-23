Owners: architect, qa

Gate PyPI and npm publishing on `bindings-smoke-windows-amd64` / `bindings-smoke-windows-arm64`, which install the zig-built Windows wheel and staged npm library on GitHub-hosted `windows-2025` / `windows-11-arm` and run both binding suites via `scripts/bindings.sh smoke`. This is the only GitHub-hosted runner exception, pinned per job in `tests/ci/self_hosted_runner_test.go` and justified in ADR 0001 (no Blacksmith Windows pool; wine cannot run x86-64 PE on the arm64 pool) (#879).
