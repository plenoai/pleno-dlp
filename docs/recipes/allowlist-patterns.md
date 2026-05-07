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
     "detector": "PIIEmail",
     "reason": "documented contact emails"},

    {"detector": "JWT", "path": "internal/testdata/**",
     "reason": "JWT samples for unit tests"}
  ]
}
```

## Operating advice

1. **Reason fields aren't optional in practice.** Without them,
   future maintainers can't tell if an entry is still valid. The
   loader doesn't enforce this, but treat empty `reason` as a
   review-block.

2. **Watch the suppression count.** pleno-dlp emits
   `allowlist: suppressed N finding(s)` to stderr. Any rule with
   zero hits across many runs is a candidate for removal — it's
   either fixed-upstream or covering a fixture that no longer
   exists.

3. **Prefer narrow over broad.** A `path: "*"` entry with a tight
   `detector` is far safer than a path-only entry that mutes
   everything in a folder.

4. **Pair with `--fail-on`.** Allowlist entries combined with
   `--fail-on critical` keeps the noise floor low while still
   blocking confirmed-active leaks.
