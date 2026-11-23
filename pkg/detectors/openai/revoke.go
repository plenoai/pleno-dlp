package openai

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

// Revoke inputs. OpenAI's admin API deletes keys by id, never by value.
// Project keys also need the owning project id; admin keys (sk-admin-) do not.
const (
	EnvRevokeAdminKey  = "PLENO_DLP_REVOKE_OPENAI_ADMIN_KEY"
	EnvRevokeProjectID = "PLENO_DLP_REVOKE_OPENAI_PROJECT_ID"
	EnvRevokeKeyID     = "PLENO_DLP_REVOKE_OPENAI_API_KEY_ID"
)

// Revoke deletes exactly the attested key: project keys via
// DELETE /v1/organization/projects/{project}/api_keys/{id}, admin keys via
// DELETE /v1/organization/admin_api_keys/{id}. It never deletes the owning
// service account. Success requires deleted=true, the exact id and the
// expected object type; 404 is the idempotent already-deleted case.
func (Scanner) Revoke(ctx context.Context, secret string) (detectors.RevokeResult, error) {
	if secret == "" {
		return detectors.RevokeResult{}, errors.New("openai: revoke: empty secret")
	}
	admin, id := revokehttp.Env(EnvRevokeAdminKey), revokehttp.Env(EnvRevokeKeyID)
	if admin == "" || id == "" {
		return detectors.RevokeResult{}, fmt.Errorf("openai: revoke: %s and %s are required", EnvRevokeAdminKey, EnvRevokeKeyID)
	}
	base := strings.TrimRight(apiBase, "/")
	var target, wantObject string
	if strings.HasPrefix(secret, "sk-admin-") {
		target = base + "/v1/organization/admin_api_keys/" + url.PathEscape(id)
		wantObject = "organization.admin_api_key.deleted"
	} else {
		project := revokehttp.Env(EnvRevokeProjectID)
		if project == "" {
			return detectors.RevokeResult{}, fmt.Errorf("openai: revoke: %s is required for project keys; legacy keys without a project need owner action", EnvRevokeProjectID)
		}
		target = base + "/v1/organization/projects/" + url.PathEscape(project) + "/api_keys/" + url.PathEscape(id)
		wantObject = "organization.project.api_key.deleted"
	}
	resp, err := revokehttp.Do(ctx, httpClient, http.MethodDelete, target,
		map[string]string{"Authorization": "Bearer " + admin}, nil)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	now := time.Now().UTC()
	switch resp.Status {
	case http.StatusOK:
	case http.StatusNotFound:
		return detectors.RevokeResult{Revoked: true, RevokedAt: now, ProviderID: id, Err: errors.New("openai: revoke: already deleted or never existed (HTTP 404)")}, nil
	default:
		return detectors.RevokeResult{}, revokehttp.StatusError("openai", resp.Status)
	}
	var body struct {
		Object  string `json:"object"`
		ID      string `json:"id"`
		Deleted bool   `json:"deleted"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return detectors.RevokeResult{}, fmt.Errorf("openai: revoke: decode response: %w", err)
	}
	if !body.Deleted || body.ID != id || body.Object != wantObject {
		return detectors.RevokeResult{ProviderID: id, Err: fmt.Errorf("openai: revoke: unconfirmed response (object=%q id-match=%t deleted=%t)", body.Object, body.ID == id, body.Deleted)}, nil
	}
	return detectors.RevokeResult{Revoked: true, RevokedAt: now, ProviderID: id}, nil
}

var _ detectors.Revoker = Scanner{}
