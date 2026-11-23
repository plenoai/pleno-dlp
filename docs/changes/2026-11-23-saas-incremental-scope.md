Owners: core-engineer, qa

SaaS connectors now pass a credential-free scope descriptor (connector name plus allowlisted non-secret config keys, with URL userinfo/query stripped) as the incremental source config, so distinct scopes of one connector keep separate `--incremental-state` entries and token rotation does not reset state. Closes #864.
