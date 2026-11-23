Owners: core-engineer, qa

`scan git` now picks the Go scheduler width from the scanned repository's
pack size. Repositories whose packs reach 64 MiB run on half the CPUs
instead of two thirds; small repositories keep two thirds. On large
histories, profiles showed that about 40% of samples went to idle Ps:
`findRunnable` netpoll (`kevent`), `osyield` on the scheduler lock, and
`madvise` on fresh spans. Moving the pipe waits off the netpoller, sharing
patch buffers, and the GOGC and `madvdontneed` knobs only moved that time
into other spin states, so total CPU did not change. Fewer Ps is the one
change that removed it. Finding sets on croc, django, and rails are
identical to main (#1038, #1035).
