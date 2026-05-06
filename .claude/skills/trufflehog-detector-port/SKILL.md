---
name: trufflehog-detector-port
description: trufflehog 호환 Detector 인터페이스(Keywords, FromData, Type, Verify)를 따르는 새 detector 를 Go 로 작성한다. AWS, GitHub PAT, Slack, OpenAI 같은 provider 시크릿 detector 추가, 기존 detector 의 정규식·키워드·Verify 함수 개선 시 이 스킬을 사용한다. detector-engineer 전용.
---

# trufflehog-detector-port

## 목적

trufflehog 본가의 `Detector` 인터페이스 시그니처를 그대로 유지하면서 Go 로 detector 를 작성한다. 시그니처 호환성 덕분에 (a) trufflehog 본가 detector 를 그대로 옮겨올 수 있고 (b) 본 detector 를 trufflehog 에 역으로 기여할 수 있다.

## 인터페이스

```go
// pkg/detectors/detectors.go
package detectors

import (
    "context"
    "regexp"
)

type DetectorType int32 // pb 패키지 사용 시 detectorspb.DetectorType

type Result struct {
    DetectorType     DetectorType
    Verified         bool
    VerificationErr  error
    Raw              []byte // 매치된 시크릿 원본
    RawV2            []byte // 보조 시크릿 (예: AWS access_key + secret 페어 시 secret)
    Redacted         string
    ExtraData        map[string]string
}

type Detector interface {
    Keywords() []string                                                 // prefilter
    FromData(ctx context.Context, verify bool, data []byte) ([]Result, error)
    Type() DetectorType
}

type Verifier interface {
    Verify(ctx context.Context, secret string) (bool, error)
}
```

## 새 detector 만드는 절차

`pkg/detectors/<provider>/<provider>.go` 에 다음 형태로 작성한다.

```go
package github

import (
    "context"
    "net/http"
    "regexp"
    "strings"

    "github.com/plenoai/pleno-secret-scanner/pkg/common/httpclient"
    "github.com/plenoai/pleno-secret-scanner/pkg/detectors"
)

type Scanner struct{ client *http.Client }

var _ detectors.Detector = (*Scanner)(nil)

// Personal access token (classic): ghp_, fine-grained: github_pat_
var pat = regexp.MustCompile(`(?i)\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b`)

func (s Scanner) Keywords() []string { return []string{"ghp_", "github_pat_"} }
func (s Scanner) Type() detectors.DetectorType { return detectors.GitHub }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
    var out []detectors.Result
    for _, m := range pat.FindAll(data, -1) {
        token := string(m)
        r := detectors.Result{
            DetectorType: s.Type(),
            Raw:          []byte(token),
            Redacted:     token[:8] + "…",
        }
        if verify {
            ok, err := s.Verify(ctx, token)
            r.Verified, r.VerificationErr = ok, err
        }
        out = append(out, r)
    }
    return out, nil
}

func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
    req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
    req.Header.Set("Authorization", "Bearer "+secret)
    req.Header.Set("Accept", "application/vnd.github+json")
    res, err := httpclient.Default().Do(req)
    if err != nil { return false, err }
    defer res.Body.Close()
    switch res.StatusCode {
    case 200: return true, nil
    case 401, 403: return false, nil
    default:    return false, fmt.Errorf("unexpected status %d", res.StatusCode)
    }
}
```

## 핵심 규칙

1. **`Keywords()` 는 비워두지 말 것.** 엔진의 prefilter 단계에서 청크에 키워드가 한 개도 없으면 `FromData` 호출이 스킵된다. 비워두면 모든 청크에 정규식이 돌아 성능이 죽는다.
2. **정규식은 `\b` 또는 lookahead 로 경계 설정.** 인접한 base64 noise 와 합쳐져 false negative 가 나는 사례 흔함.
3. **Verify 는 항상 timeout + context cancel 존중.** `httpclient.Default()` 는 5초 타임아웃 기본.
4. **HTTP 429 는 unverified 처리.** rate limit 으로 멈추지 않고 결과만 `Verified=false, VerificationErr=rate_limited` 로 표시.
5. **fixture 는 진짜 형태의 가짜 토큰만.** 실제 토큰 절대 커밋 금지. `_test.go` 에서 fixture 형식 회귀 방지.
6. **세컨더리 매칭이 필요한 detector** (예: AWS access key + secret access key 페어) 는 `RawV2` 를 채운다.

## 등록

`pkg/detectors/registry.go`:

```go
package detectors

import "github.com/plenoai/pleno-secret-scanner/pkg/detectors/github"

func init() { Register(github.Scanner{}) }
```

## 테스트

`<provider>_test.go` 최소 케이스:
- 매치 성공 (다양한 토큰 형태 1~2개)
- 매치 실패 (유사하지만 다른 키)
- Verify 200 → Verified=true
- Verify 401 → Verified=false, no err
- Verify timeout → Verified=false, err
- Keywords prefilter 가 키워드 없는 청크 빠짐

## 우선순위 detector 매트릭스

| Provider | Token shape | Verify endpoint |
|---|---|---|
| AWS | `AKIA[0-9A-Z]{16}` + 40-char secret | STS GetCallerIdentity |
| GCP_ServiceAccount | JSON key with `private_key` | OAuth2 token endpoint |
| Azure_StorageKey | base64 88-char | List containers (HEAD) |
| GitHub_PAT | `ghp_` 36 / `github_pat_` 82 | GET /user |
| GitLab_PAT | `glpat-[A-Za-z0-9_]{20}` | GET /user |
| Slack_BotToken | `xoxb-` | auth.test |
| Slack_Webhook | `https://hooks.slack.com/services/T...` | POST empty (non-2xx == invalid) |
| OpenAI_APIKey | `sk-proj-...` / `sk-...` | GET /v1/models |
| Anthropic_APIKey | `sk-ant-` | GET /v1/models |
| Stripe_SecretKey | `sk_live_` / `sk_test_` | GET /v1/account |
| JWT | 3-segment base64url | (decode + alg/iss 검증, 외부 호출 없음) |
| PrivateKey_PEM | `-----BEGIN ... PRIVATE KEY-----` | (형태만, verify 불가) |

## false-positive 회피

- detector 내부에 entropy 임계값 (≥4.0 비트/문자) 옵션 추가, 더미 토큰 (`AKIAIOSFODNN7EXAMPLE`) 은 well-known examples 리스트로 차단.
- `RedactedExamples` 변수로 AWS 공식 docs 의 예제 키, GitHub README 예시 등 well-known noise 를 제외.
