Owners: architect

Run the release `npm` job on GitHub-hosted `ubuntu-24.04-arm`: npm rejected the v0.71.4 staged publish because provenance bundles from self-hosted (Blacksmith) runners are unsupported. Pinned as the second GitHub-hosted exception in `tests/ci/self_hosted_runner_test.go` and ADR 0001; provenance and staged publishing (maintainer 2FA approval) stay on.
