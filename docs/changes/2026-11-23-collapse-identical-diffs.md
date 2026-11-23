Owners: core-engineer, connector-engineer, qa

`scan git` scans a file diff that is byte-identical to one already seen in
the walk (same path, pre-image, and post-image blob: re-added vendor trees,
cherry-picks, branch copies) only once (`git.Config.CollapseIdenticalDiffs`).
The skipped commits ride on `GitMeta.Replicas`, and the cross-commit dedup
sink expands them before picking the introducing commit, so finding sets,
commit attribution, and `occurrence_count` are unchanged (verified on croc,
django, rails). The CLI enables it only when that sink is in the chain (not
with `--all-occurrences` or `--no-dedup`). `archive.ParseVolumeName` gains a
suffix prefilter so ordinary paths skip its four regexps on every chunk
(#978).
