Owners: connector-engineer, core-engineer, qa

Render every attribute-binary text path of a merge resolution with one `git show --cc` call at the commit boundary instead of one process per path, removing the mid-scan forks that made django history scans 0.75 s slower after #997; and cap native `git log` shards at three quarters of the CPUs so shard git processes leave cores to the engine workers. Finding sets on croc, django, and rails are unchanged (#1000, #995).
