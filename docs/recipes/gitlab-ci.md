# GitLab CI integration

Run pleno-dlp on every push and surface findings in the merge request UI.

```yaml
# .gitlab-ci.yml
secret-scan:
  image: golang:1.25-alpine
  stage: test
  before_script:
    - apk add --no-cache curl tar
    - curl -sSL https://github.com/plenoai/pleno-dlp/releases/latest/download/pleno-dlp_linux_amd64.tar.gz \
        | tar xz -C /usr/local/bin pleno-dlp
  script:
    - pleno-dlp scan filesystem . --format sarif --fail-on high > findings.sarif
    - sarif-converter --type sast findings.sarif gl-sast-report.json
  artifacts:
    when: always
    reports:
      sast: gl-sast-report.json
    paths:
      - findings.sarif
```

GitLab does not ingest SARIF natively — `reports.sast` expects
GitLab's security-report JSON schema. Convert the SARIF first (e.g.
`sarif-converter --type sast findings.sarif gl-sast-report.json`) and
declare `reports: { sast: gl-sast-report.json }`. The merge-request
security widget also requires GitLab Ultimate; on other tiers keep
`findings.sarif` as a plain downloadable artifact and gate on the exit
code (`--fail-on`) instead.

## Restrict to merge-request changes

```yaml
secret-scan-mr:
  image: golang:1.25-alpine
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - git fetch origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" --depth=1
    - BASE=$(git merge-base HEAD "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
    - git diff "$BASE"...HEAD | pleno-dlp scan stdin --format sarif > findings.sarif
```

## Verification rate limiting

Verification round-trips to upstream APIs and burns rate-limit budget.
Tune the per-host limiter on the merge-to-default workflow:

```yaml
verify:
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  script:
    - pleno-dlp scan filesystem . --verify-rps 20 --fail-on critical
```
