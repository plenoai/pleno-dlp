# Project configuration (`pleno-dlp.yaml`)

`pleno-dlp scan <kind> --config FILE` (or `PLENO_DLP_CONFIG=FILE`) loads scan
flag defaults from a YAML file. There is no auto-discovery: results never
depend on the directory the binary was launched from. A missing file, an
unknown key, or a malformed value is a fatal error.

```yaml
version: 1
scan:
  format: sarif
  fail-on: medium
  exclude-detectors: [GitHub, GitLab]
  verify-rps-detector: ["AWS=2"]
  alert-webhook: ["https://hooks.slack.com/services/..."]
```

Keys under `scan` are flag names without dashes; any flag of the invoked
command (persistent scan flags and the subcommand's own flags) is accepted.

Precedence: **CLI flag > config file > built-in default**. List flags are
additive (CLI values first, then the config list).

Refused keys: anything containing `token`, `password`, `secret`, `api-key`,
`private-key`, or `credential`, plus per-run targets (`repo`, `git-url`,
`cpu-profile`). Keep credentials in the environment.

## Generating a config

```bash
pleno-dlp config init --format sarif --fail-on medium \
  --exclude-detectors GitHub --out pleno-dlp.yaml   # --force to overwrite
```

Only the flags you pass are written; defaults are omitted.
