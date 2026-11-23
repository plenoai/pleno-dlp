Owners: core-engineer, qa

Add `--format audit-html`: a self-contained compliance report with scan metadata (run ID, generator version, source kind, start/completion/duration, verification policy, chunks/bytes scanned, coverage-gap count, and the names — never values — of flags set), a verdict summary, and findings ordered verified → indeterminate → unverified then by severity, carrying only the redacted display, assurance, location, and secret SHA-256 (#870).
