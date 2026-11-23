Owners: connector-engineer, core-engineer, qa

The in-process git renderer now hands each rendered file patch straight to
the parser on the same goroutine instead of writing whole commits through
an `io.Pipe` that a second goroutine re-buffered and re-split (#1041). If
an unreadable blob forces a git fallback after earlier files of a commit
were sent, git's rendering of that commit is forwarded minus the header and
the sections already sent, so the stream stays byte-identical to
`git log -p`. Renderers skip the per-worker `git check-attr` helper when the
walk can prove no attribute source exists: a non-bare repository, no
`.gitattributes` in the worktree or index, and no `info/attributes`, global
or system file, `core.attributesFile`, `attr.tree`, or `GIT_ATTR_SOURCE`
(#1042). Repositories with packs under 32 MiB scan on a third of the CPUs
(#1035). On a 30-CPU host (hyperfine median, CPU-s / wall s), croc git
goes from 2.08/0.21 to 1.56/0.23, against kingfisher's 1.11/0.27. django
and rails are unchanged. Finding sets on croc, django, and rails are
identical to main.
