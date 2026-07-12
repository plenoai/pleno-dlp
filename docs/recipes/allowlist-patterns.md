# Allowlist patterns

Common false-positive shapes and the `.pleno-allow.json` entries
that mute them. Drop these into `.pleno-allow.json` at your repo
root — pleno-dlp auto-discovers it.

```json
{
  "entries": [
    {"detector": "AWS",         "raw": "AKIAIOSFODNN7EXAMPLE",
     "reason": "trufflehog test fixture"},
    {"detector": "AWS",         "raw_regex": "^AKIA[A-Z0-9]+EXAMPLE$",
     "reason": "any AWS key ending in EXAMPLE is a documentation sample"},

    {"detector": "GenericHighEntropy", "raw_regex": "^sha256:[a-f0-9]{64}$",
     "reason": "image digest, not a credential"},
    {"detector": "GenericHighEntropy", "path": "go.sum",
     "reason": "module hashes"},
    {"detector": "GenericHighEntropy", "path": "package-lock.json",
     "reason": "npm lockfile hashes"},

    {"detector": "Stripe",      "raw_regex": "^sk_test_",
     "reason": "Stripe test-mode keys"},

    {"detector": "GitHub",      "raw_regex": "^ghp_test",
     "reason": "internal staging token"},

    {"path": "fixtures/**/*.env",
     "reason": "local test fixtures"},
    {"path": "**/*.example",
     "reason": "documented .example files are not real configs"},
    {"path": "docs/**",
     "detector": "PIIAnonymize",
     "raw_regex": "@example\\.com$",
     "reason": "documented contact emails — PIIAnonymize emits one detector type for all PII; filter on the matched value (or extra_data.pii_kind in JSON output) to scope by entity type"},

    {"detector": "JWT", "path": "internal/testdata/**",
     "reason": "JWT samples for unit tests"}
  ]
}
```

## Operating advice

Give every entry a `reason`. Without one, future maintainers can't
tell if the entry is still valid; the loader accepts an empty
`reason`, so make code review the point where it gets rejected.

pleno-dlp emits `allowlist: suppressed N finding(s)` to stderr.
Watch that count: any rule with zero hits across many runs is a
candidate for removal, because either the finding was fixed upstream
or the fixture it covered no longer exists.

Scope entries narrowly. A `path: "*"` entry with a tight `detector`
is far safer than a path-only entry that mutes everything in a
folder. Allowlist entries combined with `--fail-on critical` keep
the noise floor low while still blocking Critical findings.
