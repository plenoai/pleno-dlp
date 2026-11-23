Owners: architect

Install `libc6-dev-amd64-cross` for the linux-amd64 `bindings-lib` cross
build; v0.70.0 failed because cgo found no x86-64 glibc headers
(`bits/libc-header-start.h`) on the arm64 runner.
