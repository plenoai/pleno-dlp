package anthropic

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

// Revoke inputs. Anthropic exposes no raw-key-to-id lookup, so the operator
// supplies an Admin API key and the exact API key id from the console.
const (
	EnvRevokeAdminKey = "PLENO_DLP_REVOKE_ANTHROPIC_ADMIN_KEY"
	EnvRevokeKeyID    = "PLENO_DLP_REVOKE_ANTHROPIC_API_KEY_ID"
)

// Revoke deactivates the API key via the Admin API
// (POST /v1/organizations/api_keys/{id} {"status":"inactive"}). Success
// requires the provider to echo type=api_key, the exact id, and
// status=inactive; re-deactivating an inactive key is idempotent.
func (Scanner) Revoke(ctx context.Context, secret string) (detectors.RevokeResult, error) {
	if secret == "" {
		return detectors.RevokeResult{}, errors.New("anthropic: revoke: empty secret")
	}
	if strings.HasPrefix(secret, "sk-ant-admin") {
		return detectors.RevokeResult{}, errors.New("anthropic: revoke: admin keys are unsupported; revoke them manually in the console")
	}
	admin, id := revokehttp.Env(EnvRevokeAdminKey), revokehttp.Env(EnvRevokeKeyID)
	if admin == "" || id == "" {
		return detectors.RevokeResult{}, fmt.Errorf("anthropic: revoke: %s and %s are required (no raw-key-to-id lookup exists)", EnvRevokeAdminKey, EnvRevokeKeyID)
	}
	resp, err := revokehttp.Do(ctx, httpClient, http.MethodPost,
		strings.TrimRight(apiBase, "/")+"/v1/organizations/api_keys/"+url.PathEscape(id),
		map[string]string{
			"x-api-key":         admin,
			"anthropic-version": "2023-06-01",
			"content-type":      "application/json",
		}, strings.NewReader(`{"status":"inactive"}`))
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	if resp.Status != http.StatusOK {
		return detectors.RevokeResult{}, revokehttp.StatusError("anthropic", resp.Status)
	}
	var body struct {
		Type   string `json:"type"`
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return detectors.RevokeResult{}, fmt.Errorf("anthropic: revoke: decode response: %w", err)
	}
	if body.Type != "api_key" || body.ID != id || body.Status != "inactive" {
		return detectors.RevokeResult{ProviderID: id, Err: fmt.Errorf("anthropic: revoke: unconfirmed response (type=%q id-match=%t status=%q)", body.Type, body.ID == id, body.Status)}, nil
	}
	return detectors.RevokeResult{Revoked: true, RevokedAt: time.Now().UTC(), ProviderID: id}, nil
}

var _ detectors.Revoker = Scanner{}
