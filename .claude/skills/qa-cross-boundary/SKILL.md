---
name: qa-cross-boundary
description: detector·source·engine·output 의 경계면 정합성을 검증한다. 인터페이스(Detector, Source, Result, Chunk) 시그니처 일치, chunk metadata 가 출력까지 살아 전달되는지, race detector 통과, e2e CLI 시나리오 통과를 확인한다. qa 에이전트 전용. 새 detector·source 통합 직후, 인터페이스 변경 후, 회귀 의심 시 사용한다.
---

# qa-cross-boundary

## 목적

존재 확인이 아니라 **경계면 교차 비교** 를 한다. 각 모듈이 단독으로는 컴파일·테스트 통과해도, 모듈끼리 만나는 지점에서 shape 불일치가 흔히 발생한다. 본 스킬은 그 경계의 정합성에 집중한다.

## 검증 매트릭스

| ID | 경계 | 검증 방법 | 빈도 |
|---|---|---|---|
| B1 | Detector interface | 모든 detector 가 `Detector` interface 충족 + `var _ detectors.Detector = (*Scanner)(nil)` 컴파일 가드 | detector 추가/수정 시 |
| B2 | Source interface | 모든 source 가 `Source` interface 충족 | source 추가/수정 시 |
| B3 | Chunk → detector prefilter | 각 source 의 대표 fixture 청크에 대해 적어도 1개 detector 의 키워드가 매칭되는지 (그렇지 않으면 source 가 "의미있는" 데이터를 emit 하지 않는 것) | source 추가 시 |
| B4 | Result → output | detector 가 emit 한 모든 필드 (Type, Verified, Raw redacted, RawV2, Redacted, ExtraData) 가 JSON·SARIF·table 출력 각각에서 살아남는지 | detector 추가/수정, output 수정 시 |
| B5 | metadata 전파 | source 가 채운 SourceMetadata 가 Chunk → Result → output 까지 살아 도달하는지 (특히 SARIF locations) | source/output 수정 시 |
| B6 | race | `go test ./... -race -count=1` 통과 | PR 마다 |
| B7 | e2e CLI | testdata fixture 5개 (filesystem with AWS, git with GH PAT, github mock with Slack, etc.) 에 대해 CLI 실행 후 expected 결과 매칭 | PR 마다 |
| B8 | Verify 폴백 | 각 detector 의 Verify 가 mock 서버에서 200/401/429/timeout 4가지 케이스 정상 처리 | Verify 수정 시 |

## 절차

### 1. 인터페이스 정합 (B1, B2)

```bash
go build ./...
go vet ./...
```

`var _ detectors.Detector = (*Scanner)(nil)` 같은 컴파일타임 가드 누락된 detector·source 색출:

```bash
rg -L 'var _ (detectors\.Detector|sources\.Source)' pkg/detectors pkg/sources
```

누락 발견 시 owner 에게 SendMessage + TaskCreate.

### 2. 키워드 prefilter (B3)

각 source 의 fixture 청크 상에서 detector 키워드 hit 통계 수집. fixture 가 모두 키워드 미스면 fixture 가 잘못 만들어진 것 (실제 데이터 시그널 부재).

```go
// tests/integration/prefilter_test.go
for _, src := range sourceFixtures {
    chunks := src.collectChunks(t)
    for _, det := range registry.All() {
        hits := countKeywordHits(chunks, det.Keywords())
        if hits == 0 && expected[src.Type()][det.Type()] {
            t.Errorf("%s/%s: expected keyword hits, got 0", src.Type(), det.Type())
        }
    }
}
```

### 3. Result/metadata 전파 (B4, B5)

대표 fixture 1개를 골라:
- detector 가 만든 Result 의 모든 필드 → JSON output 의 필드와 1:1 비교
- SARIF output 의 `locations[0].physicalLocation` 이 source metadata 에서 옴을 확인

```go
got := runScan(t, "testdata/git-with-ghpat")
require.Equal(t, "GitHub", got.Results[0].DetectorType)
require.NotEmpty(t, got.Results[0].Source.Git.Commit)
require.NotEmpty(t, got.Results[0].Source.Git.File)
```

### 4. race (B6)

```bash
go test ./... -race -count=1 -timeout 5m
```

flaky 테스트는 별도 `_workspace/flaky-tests.md` 에 기록 + 우선 수리 대상.

### 5. e2e CLI (B7)

`tests/e2e/` 에 셸 기반 시나리오:

```bash
# tests/e2e/01_filesystem_aws.sh
set -euo pipefail
out=$(./bin/pleno-secret-scanner filesystem testdata/aws-key/ --json --no-verification)
echo "$out" | jq -e '.[] | select(.detector_type=="AWS")' > /dev/null
```

### 6. Verify mock (B8)

`pkg/common/httpclient/testserver.go` 에 mock 서버 헬퍼. 각 detector 의 `_verify_test.go` 가 4 시나리오 (200/401/429/timeout) 를 돌려야 함.

## 회귀 보고 형식

`_workspace/qa-report-<YYYY-MM-DD>.md`:

```markdown
## 회귀: <한줄 요약>

- 시나리오: <어떤 입력/조건>
- 기대: <어떤 결과가 나와야 하는가>
- 실제: <무엇이 일어났는가, 출력 일부 첨부>
- 영향 모듈: pkg/...
- 재현: `go test ./pkg/.../  -run Test...` or `./bin/pleno-secret-scanner ...`
- 추정 원인: <인터페이스 mismatch / metadata 누락 / race / 기타>
- Owner: @<agent>
```

## 작동 원칙

1. **자동 수정 시도하지 않는다.** 발견·재현·보고에 집중. 수정은 owner 의 책임.
2. **flaky 처리.** 동일 테스트가 3회 중 1회만 실패하면 즉시 `_workspace/flaky-tests.md` 등록 + owner 알림. 무시하지 않는다.
3. **실 API 호출 금지.** Verify 는 항상 mock 서버. 실 토큰 사용 금지.
4. **incremental.** 모듈 통합마다 즉시 검증. 한꺼번에 검증하면 원인 추적 비용이 폭증.

## 이전 산출물이 있을 때

`_workspace/qa-report-*.md` 최근 5건과 `_workspace/flaky-tests.md` 를 먼저 읽고, 같은 패턴이 다시 잡히는지 우선 확인한다. 반복 회귀는 근본 원인 ADR 작성 요청.
