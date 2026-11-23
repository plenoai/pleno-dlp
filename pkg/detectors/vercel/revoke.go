package vercel

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/revokehttp"
)

// Revoke self-deletes a personal or integration token through
// DELETE /v3/user/tokens/current authenticated by the token itself. A 401/403
// means the token no longer authenticates, which is the idempotent case.
func (Scanner) Revoke(ctx context.Context, secret string) (detectors.RevokeResult, error) {
	if secret == "" {
		return detectors.RevokeResult{}, errors.New("vercel: revoke: empty secret")
	}
	resp, err := revokehttp.Do(ctx, httpClient, http.MethodDelete,
		strings.TrimRight(apiBase, "/")+"/v3/user/tokens/current",
		map[string]string{"Authorization": "Bearer " + secret}, nil)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	now := time.Now().UTC()
	id := revokehttp.Fingerprint(secret)
	switch resp.Status {
	case http.StatusOK, http.StatusNoContent:
		return detectors.RevokeResult{Revoked: true, RevokedAt: now, ProviderID: id}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return detectors.RevokeResult{Revoked: true, RevokedAt: now, ProviderID: id, Err: errors.New("vercel: revoke: token no longer authenticates (already revoked or invalid)")}, nil
	default:
		return detectors.RevokeResult{}, revokehttp.StatusError("vercel", resp.Status)
	}
}

var _ detectors.Revoker = Scanner{}
