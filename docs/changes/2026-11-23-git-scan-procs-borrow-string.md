Owners: core-engineer, detector-engineer, qa

Cap the Go scheduler at max(4, 2/3 of the CPUs) for local `scan git` unless
`GOMAXPROCS` is set, because the `git log --patch` shard children occupy
the remaining cores. Add `detectors.BorrowString` so the config-file
detectors (json/php/django config, hardcodedpassword, netrc, esmtprc,
npmrcauth) and generic keyword lowering stop copying each chunk into a
string. Retained `ExtraData` substrings are cloned. Hyperfine medians on a
30-CPU host, CPU including git children: croc 2.95→2.77, django 42.8→41.2,
rails 44.3→43.8 CPU-s. Wall time is equal or lower, and the finding sets
are identical (#1018).
