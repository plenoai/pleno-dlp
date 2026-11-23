Owners: core-engineer, qa

Add `pleno-dlp validate --detector <type> --secret <value|->`, which runs one registered detector with live verification over operator-supplied text (stdin recommended, 64 KiB cap), prints redacted verdicts as table or JSON, honours the AWS canary skip list, and exits 0 only when a match verifies. Part of #870 (epic #817).
