Owners: detector-engineer, core-engineer, qa

The AWS detector decodes the owning account from the access key ID offline (`aws_account_id`) and never calls STS for keys on the canary skip list (built-in Thinkst canarytokens accounts plus `--skip-aws-account` / `--skip-aws-account-file`), tagging them `verification_skipped=canary_account`. Part of #870 (epic #817).
