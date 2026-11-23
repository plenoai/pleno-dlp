Owners: connector-engineer, qa

The in-process history stream now feeds rendered patch text straight into
the parser on the renderer's goroutine (`nativeLogParser.feed`) instead of
through an `io.Pipe` and a second goroutine. A commit git must render still
streams through `parseStream`. The walk-wide binary-blob and `diff`
attribute caches are split into 64 read-write-locked stripes, replacing
the single mutexes that serialized all renderers (#1033).

Finding sets (detector, secret hash, path, commit, line, occurrence count)
are identical on croc, django, and rails. CPU savings are small (about
0.5 CPU-s on django and rails).

An in-process replacement for the `git log --raw` tree diff gave
byte-identical records on all three corpora but was not a CPU win (rails
36.9 vs 34.7 CPU-s). It is left out of this change and kept on branch
`perf/issue1033-treediff-experiment`.
