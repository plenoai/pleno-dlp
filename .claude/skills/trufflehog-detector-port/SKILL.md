---
name: trufflehog-detector-port
description: Author or revise Go detectors that conform to trufflehog's Detector interface (Keywords, FromData, Type, Verify). Use when adding detectors for providers like AWS, GitHub PAT, Slack, or OpenAI; or when tightening regexes, keywords, or Verify functions for an existing detector. detector-engineer only.
---

# trufflehog-detector-port

## Purpose

Author Go detectors that match trufflehog's `Detector` interface signature exactly. Signature-level compatibility means (a) trufflehog upstream detectors can be ported in directly, and (b) detectors written here can be contributed back upstream.

## Interface

```go
// pkg/detectors/detectors.go
package detectors

import (
    "context"
)

type DetectorType int32 // or detectorspb.DetectorType

type Result struct {
    DetectorType    DetectorType
    Verified        bool
    VerificationErr error
    Raw             []byte // matched secret bytes
    RawV2           []byte // paired secret (e.g. AWS secret access key)
    Redacted        string
    ExtraData       map[string]string
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

## Adding a new detector

Place `pkg/detectors/<provider>/<provider>.go`:

```go
package github

import (
    "context"
    "fmt"
    "net/http"
    "regexp"

    "github.com/plenoai/pleno-dlp/pkg/common/httpclient"
    "github.com/plenoai/pleno-dlp/pkg/detectors"
)

type Scanner struct{ client *http.Client }

var _ detectors.Detector = (*Scanner)(nil)

// Personal access token (classic) and fine-grained.
var pat = regexp.MustCompile(`(?i)\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b`)

func (s Scanner) Keywords() []string         { return []string{"ghp_", "github_pat_"} }
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
    if err != nil {
        return false, err
    }
    defer res.Body.Close()
    switch res.StatusCode {
    case 200:
        return true, nil
    case 401, 403:
        return false, nil
    default:
        return false, fmt.Errorf("unexpected status %d", res.StatusCode)
    }
}
```

## Core rules

1. **Never leave `Keywords()` empty.** The engine skips chunks containing none of the returned keywords; emptiness defeats the prefilter and tanks performance.
2. **Anchor regexes** with `\b` or lookaheads — adjacent base64 noise is a common source of false negatives.
3. **Verify must honour timeouts and context cancellation.** `httpclient.Default()` provides a 5-second timeout by default.
4. **Treat HTTP 429 as unverified.** Do not retry; do not stall the scan. `Verified=false, VerificationErr=rate_limited`.
5. **Fixtures are realistically shaped fake tokens only.** Real tokens never get committed. Add `<provider>_test.go` for shape regression coverage.
6. **Paired-secret detectors** (e.g. AWS key id + secret access key) populate `RawV2`.

## Registration

`pkg/detectors/registry.go`:

```go
package detectors

import _ "github.com/plenoai/pleno-dlp/pkg/detectors/github"
```

Or register explicitly via `init()`:

```go
func init() { Register(Scanner{}) }
```

## Tests

Minimal `<provider>_test.go` cases:
- Match success (one or two realistic token shapes)
- Match failure (similar-but-different keys)
- Verify 200 → `Verified=true`
- Verify 401 → `Verified=false`, no error
- Verify timeout → `Verified=false`, error set
- Keyword prefilter rejects keyword-free chunks

## Priority detector matrix

| Provider | Token shape | Verify endpoint |
|---|---|---|
| AWS | `AKIA[0-9A-Z]{16}` + 40-char secret | STS GetCallerIdentity |
| GCP_ServiceAccount | JSON key with `private_key` | OAuth2 token endpoint |
| Azure_StorageKey | base64 88-char | List containers (HEAD) |
| GitHub_PAT | `ghp_` (36) / `github_pat_` (82) | GET /user |
| GitLab_PAT | `glpat-[A-Za-z0-9_]{20}` | GET /user |
| Slack_BotToken | `xoxb-` | auth.test |
| Slack_Webhook | `https://hooks.slack.com/services/T...` | POST empty body (non-2xx == invalid) |
| OpenAI_APIKey | `sk-proj-...` / `sk-...` | GET /v1/models |
| Anthropic_APIKey | `sk-ant-` | GET /v1/models |
| Stripe_SecretKey | `sk_live_` / `sk_test_` | GET /v1/account |
| JWT | three base64url segments | local: decode + alg/iss check, no network |
| PrivateKey_PEM | `-----BEGIN ... PRIVATE KEY-----` | shape-only, unverifiable |

## False-positive guards

- Keep an entropy threshold (≥4.0 bits/char) inside the detector and skip well-known examples (`AKIAIOSFODNN7EXAMPLE`, official docs samples).
- Maintain a `RedactedExamples` list for canonical noise (AWS docs example keys, GitHub README placeholders).
