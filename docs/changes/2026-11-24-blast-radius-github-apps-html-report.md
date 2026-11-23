Owners: core-engineer, connector-engineer, qa

Map GitHub fine-grained PATs, GitHub App user-to-server tokens (installations with their permissions and repositories), and installation tokens (`/installation/repositories`), recording token expiry. Add the HTML access-map report `pkg/blastradius/htmlreport` with `blast-radius --html` and `blast-radius report <scan.jsonl>` (kingfisher `--view-report` equivalent). Completes #848 (epic #817).
