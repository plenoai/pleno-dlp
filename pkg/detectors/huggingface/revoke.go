package huggingface

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/revokehttp"
)

// Revoke reports the token to Hugging Face's unauthenticated
// POST /api/credentials/revoke. The endpoint answers 202 for any input,
// so success maps to Outcome=accepted with Revoked=false: it is not
// proof of invalidation (#859).
func (Scanner) Revoke(ctx context.Context, secret string) (detectors.RevokeResult, error) {
	if secret == "" {
		return detectors.RevokeResult{}, errors.New("huggingface: revoke: empty secret")
	}
	payload, err := json.Marshal(map[string][]string{"credentials": {secret}})
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	resp, err := revokehttp.Do(ctx, httpClient, http.MethodPost,
		strings.TrimRight(apiBase, "/")+"/api/credentials/revoke",
		map[string]string{"Content-Type": "application/json"}, bytes.NewReader(payload))
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	if resp.Status != http.StatusAccepted {
		return detectors.RevokeResult{}, revokehttp.StatusError("huggingface", resp.Status)
	}
	return detectors.RevokeResult{
		Revoked:    false,
		Outcome:    detectors.RevokeAccepted,
		RevokedAt:  time.Now().UTC(),
		ProviderID: revokehttp.Fingerprint(secret),
		Err:        errors.New("huggingface: revoke: report accepted (HTTP 202); provider does not confirm invalidation"),
	}, nil
}

var _ detectors.Revoker = Scanner{}
