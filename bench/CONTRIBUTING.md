# Contributing to dlp-bench

Best-effort guide — this directory is smaller in scope than the main
detector/source codebase, so the bar is "don't regress reproducibility,"
not a full review process.

## Adding a synthetic fixture type

1. Confirm the type has a real regex you can inspect: read the
   detector's `.go` file (not just its `_test.go`) for the exact
   `regexp.MustCompile` pattern and `Keywords()` list. Reusing the
   detector's own literal test fixture verbatim is the safest source —
   it's already proven format-valid by that detector's own passing test.
2. Add a `fixture{}` entry to `bench/gen/spec.go`. Use the `token()`
   helper (never `sample()` directly for the credential itself) so the
   placeholder-filter check runs automatically.
3. Run `go test ./bench/gen/... -race -run TestFixtures_DetectedByPlenoDLP/<slug>`.
   If it fails, that's either a fixture bug (re-check the regex) or a
   genuine detector bug (see below) — don't loosen the fixture just to
   make the test pass.
4. Run `go run ./bench/gen -out /tmp/check && cat /tmp/check/<slug>.txt`
   and sanity-read it: does it look like a real leaked credential in a
   real config file, not a test fixture?

## A fixture reveals a detector bug, not a fixture bug

This has already happened once (`azure-storage-account-key`, see
`bench/README.md`). Do not "fix" the fixture to route around it:

1. Add an entry to `bench/gen/spec.go`'s `knownMisses` map, keyed by
   slug, explaining the bug with a file:line reference.
2. Keep the fixture in its *realistic* shape — the whole point is that
   the corpus reflects what a real leak looks like, not what the
   detector currently happens to catch.
3. File a follow-up issue for detector-engineer scope; don't fix the
   detector in the same change as a bench-tooling PR.
4. `TestFixtures_DetectedByPlenoDLP` will assert the miss instead of the
   hit — when the detector is eventually fixed, that test starts
   failing until the `knownMisses` entry is removed, which is the
   intended signal.

## Bumping a pinned tool version (trufflehog / gitleaks)

Both files must move together in the same diff:

- `bench/harness/tools.go`'s `pinnedVersion` map (informational —
  documents what this harness was validated against).
- `bench/scripts/fetch-tools.sh`'s version constants and every
  platform's sha256, copied from that release's own
  `*_checksums.txt` asset (e.g.
  `https://github.com/gitleaks/gitleaks/releases/download/vX.Y.Z/gitleaks_X.Y.Z_checksums.txt`).
  Do not hand-compute or guess a checksum.

Then run `make bench-clean bench` end to end and confirm the recall
numbers still look sane (a version bump changing a tool's own detection
rules is expected and fine; a harness parse error is not — check
`bench/harness/parse.go` still matches that release's JSON schema).

## Adding a second real-world corpus

Follow `bench/harness/leakyrepo.go` as the template:

- Pin an exact commit, not a branch.
- Strip `.git` after cloning (trufflehog's filesystem source reads
  `.git` internals directly, which would make its finding count
  incomparable to the other two tools — see `docs/comparison.md` §7).
- Ground truth should come from the upstream project's own inventory of
  seeded secrets if one exists (as leaky-repo's `.leaky-meta/secrets.csv`
  does) rather than a label file this project authors — we can't
  adversarially audit our own claims about someone else's repository as
  confidently as the repo's own maintainers can.
- If no such upstream inventory exists, treating a curated public issue
  tracker / README table as ground truth is the fallback
  `docs/comparison.md` §3's terragoat and juice-shop rows already use —
  document the derivation method inline, same as those sections do.

## Style

Keep it minimal: this directory has no product surface of its own, so
every abstraction needs to earn its place against "will a third party
actually need this to reproduce the numbers." Prefer a slightly more
manual step documented in `bench/README.md` over a generalized
configuration system for a use case that doesn't exist yet.
