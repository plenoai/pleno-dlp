# Aho-Corasick matcher (`pkg/ahocorasick`)

Design rationale for the in-repo Aho-Corasick multi-pattern matcher used
by the engine as a keyword prefilter across all registered detectors.

Two design choices justify rolling our own instead of pulling in a third
party module:

- The matcher is on the engine's hot path (called once per chunk variant).
  We need predictable allocation behaviour and a `Match()` API that returns
  pattern IDs, not byte offsets — that lets the engine accumulate a
  "which detectors fire" set with zero string materialisation.
- Dependency policy in CLAUDE.md is conservative; adding a transitive dep
  for a 200-line algorithm is the wrong trade-off.

The matcher is case-sensitive. Callers that need case-insensitive matching
(the engine does) are expected to lower-case both the patterns at build
time and the input at scan time. Doing the lowercasing here would force
every `Match()` call to allocate; pushing it to the caller lets them reuse
a pooled buffer.