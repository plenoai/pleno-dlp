Owners: connector-engineer

The native git cost pass (`git log --raw` per-commit changed paths) now starts with the rev-list on the same revision input instead of after it, and is cancelled once the history exceeds the 20,000-commit cost-plan limit; it walks a superset of the selection and extra commits are ignored. Finding sets are unchanged on croc, rails and django (part of #978).
