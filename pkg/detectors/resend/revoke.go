package resend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/revokehttp"
)

// Revoke inputs. Sending-only keys cannot manage keys, so the operator
// supplies a full-access key plus the leaked key's UUID.
const (
	EnvRevokeAdminKey = "PLENO_DLP_REVOKE_RESEND_ADMIN_API_KEY"
	EnvRevokeKeyID    = "PLENO_DLP_REVOKE_RESEND_API_KEY_ID"
)

var uuidRe = detectors.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Revoke deletes one key (DELETE /api-keys/{id}). Success requires
// object=api_key, the exact id and deleted=true; 404 is idempotent.
func (Scanner) Revoke(ctx context.Context, secret string) (detectors.RevokeResult, error) {
	if secret == "" {
		return detectors.RevokeResult{}, errors.New("resend: revoke: empty secret")
	}
	admin, id := revokehttp.Env(EnvRevokeAdminKey), revokehttp.Env(EnvRevokeKeyID)
	if admin == "" || id == "" {
		return detectors.RevokeResult{}, fmt.Errorf("resend: revoke: %s and %s are required", EnvRevokeAdminKey, EnvRevokeKeyID)
	}
	if !uuidRe.MatchString(id) {
		return detectors.RevokeResult{}, fmt.Errorf("resend: revoke: %s must be a key UUID", EnvRevokeKeyID)
	}
	resp, err := revokehttp.Do(ctx, httpClient, http.MethodDelete,
		strings.TrimRight(apiBase, "/")+"/api-keys/"+url.PathEscape(id),
		map[string]string{"Authorization": "Bearer " + admin}, nil)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	now := time.Now().UTC()
	switch resp.Status {
	case http.StatusOK:
	case http.StatusNotFound:
		return detectors.RevokeResult{Revoked: true, RevokedAt: now, ProviderID: id, Err: errors.New("resend: revoke: already deleted or never existed (HTTP 404)")}, nil
	default:
		return detectors.RevokeResult{}, revokehttp.StatusError("resend", resp.Status)
	}
	var body struct {
		Object  string `json:"object"`
		ID      string `json:"id"`
		Deleted bool   `json:"deleted"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return detectors.RevokeResult{}, fmt.Errorf("resend: revoke: decode response: %w", err)
	}
	if body.Object != "api_key" || body.ID != id || !body.Deleted {
		return detectors.RevokeResult{ProviderID: id, Err: fmt.Errorf("resend: revoke: unconfirmed response (object=%q id-match=%t deleted=%t)", body.Object, body.ID == id, body.Deleted)}, nil
	}
	return detectors.RevokeResult{Revoked: true, RevokedAt: now, ProviderID: id}, nil
}

var _ detectors.Revoker = Scanner{}
