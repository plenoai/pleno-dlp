# GitLab CI integration

Run pleno-dlp on every push, write a SAST-format report, and surface
findings in the merge request UI.

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
  artifacts:
    when: always
    reports:
      sast: findings.sarif
    paths:
      - findings.sarif
```

GitLab consumes SARIF natively under `reports.sast`; findings appear
in the merge-request "Security & Compliance" tab without further
configuration.

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

## Verify on protected branches only

`--verify` round-trips to upstream APIs and burns rate-limit budget.
Restrict it to the merge-to-default workflow:

```yaml
verify:
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  script:
    - pleno-dlp scan filesystem . --verify --verify-rps 20 --fail-on critical
```
