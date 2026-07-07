package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://gitlab.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b(glpat-[A-Za-z0-9_-]{20})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GitLab }

func (Scanner) Keywords() []string { return []string{"glpat-"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	for _, m := range matches {
		token := string(m)
		res := detectors.Result{
			DetectorType: detectors.GitLab,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			v, err := s.Verify(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/v4/personal_access_tokens/self", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("PRIVATE-TOKEN", secret)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
}

func (Scanner) Revoke(ctx context.Context, secret string) (detectors.RevokeResult, error) {
	if secret == "" {
		return detectors.RevokeResult{}, errors.New("gitlab: revoke: empty secret")
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	now := func() time.Time { return time.Now().UTC() }

	selfReq, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/v4/personal_access_tokens/self", nil)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	selfReq.Header.Set("Authorization", "Bearer "+secret)
	selfReq.Header.Set("Accept", "application/json")

	selfResp, err := httpClient.Do(selfReq)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, selfResp.Body)
		_ = selfResp.Body.Close()
	}()

	switch selfResp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return detectors.RevokeResult{
			Revoked:   true,
			RevokedAt: now(),
			Err:       errors.New("gitlab: token already revoked or invalid"),
		}, nil
	case http.StatusTooManyRequests:
		return detectors.RevokeResult{}, errors.New("gitlab: revoke: rate-limited resolving token id (HTTP 429)")
	default:
		snippet, _ := io.ReadAll(io.LimitReader(selfResp.Body, 256))
		return detectors.RevokeResult{}, fmt.Errorf("gitlab: revoke: unexpected status resolving token id: %s: %s", selfResp.Status, string(snippet))
	}

	var parsed struct {
		ID int64 `json:"id"`
	}
	body, err := io.ReadAll(io.LimitReader(selfResp.Body, 1<<14))
	if err != nil {
		return detectors.RevokeResult{}, fmt.Errorf("gitlab: revoke: read self body: %w", err)
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return detectors.RevokeResult{}, fmt.Errorf("gitlab: revoke: decode self body: %w", err)
	}
	if parsed.ID == 0 {
		return detectors.RevokeResult{}, errors.New("gitlab: revoke: self response missing id")
	}
	idStr := strconv.FormatInt(parsed.ID, 10)

	revokeReq, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/api/v4/personal_access_tokens/"+idStr+"/revoke", nil)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	revokeReq.Header.Set("Authorization", "Bearer "+secret)

	revokeResp, err := httpClient.Do(revokeReq)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, revokeResp.Body)
		_ = revokeResp.Body.Close()
	}()

	switch revokeResp.StatusCode {
	case http.StatusNoContent:
		return detectors.RevokeResult{Revoked: true, RevokedAt: now(), ProviderID: idStr}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return detectors.RevokeResult{
			Revoked:    true,
			RevokedAt:  now(),
			ProviderID: idStr,
			Err:        errors.New("gitlab: token already revoked"),
		}, nil
	case http.StatusNotFound:
		return detectors.RevokeResult{
			Revoked:    true,
			RevokedAt:  now(),
			ProviderID: idStr,
			Err:        errors.New("gitlab: token not found"),
		}, nil
	case http.StatusTooManyRequests:
		return detectors.RevokeResult{}, errors.New("gitlab: revoke: rate-limited (HTTP 429)")
	default:
		snippet, _ := io.ReadAll(io.LimitReader(revokeResp.Body, 256))
		return detectors.RevokeResult{}, fmt.Errorf("gitlab: revoke: unexpected status %s: %s", revokeResp.Status, string(snippet))
	}
}

func redact(t string) string {
	if len(t) <= 10 {
		return t
	}
	return t[:10] + "..."
}

var (
	_ detectors.Detector = Scanner{}
	_ detectors.Verifier = Scanner{}
	_ detectors.Revoker  = Scanner{}
)

func init() {
	detectors.Register(Scanner{})
}
