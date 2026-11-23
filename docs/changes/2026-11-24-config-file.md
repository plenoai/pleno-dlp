Owners: core-engineer, qa

Add `scan --config FILE` / `PLENO_DLP_CONFIG` (versioned `pleno-dlp.yaml`; keys are scan flag names, CLI > config > default, list flags additive, unknown keys and credential/target flags rejected) and `pleno-dlp config init` that emits a config from the scan flags passed, omitting defaults and refusing to overwrite without `--force`; documented in `docs/config.md` (#870).
