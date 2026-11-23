# Scan attribute-binary text introduced by merge resolutions

- Date: 2026-11-23
- Owners: connector-engineer, qa
- Issue: #994

The native git walker force-renders text files marked binary by
`.gitattributes` with `git show --text`. For merge commits that rendered
nothing (`--diff-merges=off`), and combined diffs ignore `--text`, so a
secret written while resolving a conflict in such a file was never scanned.
Merges now render with `--cc`, attributes read from the empty tree
(`--attr-source`, git >= 2.40) and `core.attributesFile` disabled, parsed by
the combined-diff parser. A git without `--attr-source` records a
`merge-forced-text` coverage gap instead of failing the walk. The go-git
walker already sniffs content rather than attributes; both paths are pinned
by `mergeattr_test.go`. Unique findings on croc/django/rails are unchanged.
