package notion

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/revokehttp"
)

// Revoke inputs: the public integration that issued the OAuth token.
// Internal integration tokens cannot be revoked by API.
const (
	EnvRevokeClientID     = "PLENO_DLP_REVOKE_NOTION_CLIENT_ID"
	EnvRevokeClientSecret = "PLENO_DLP_REVOKE_NOTION_CLIENT_SECRET"
)

// Revoke runs introspect → revoke → introspect against the issuing app.
// An already-inactive token is the idempotent case; success requires the
// second introspection to report active=false.
func (Scanner) Revoke(ctx context.Context, secret string) (detectors.RevokeResult, error) {
	if secret == "" {
		return detectors.RevokeResult{}, errors.New("notion: revoke: empty secret")
	}
	cid, csec := revokehttp.Env(EnvRevokeClientID), revokehttp.Env(EnvRevokeClientSecret)
	if cid == "" || csec == "" {
		return detectors.RevokeResult{}, fmt.Errorf("notion: revoke: %s and %s are required; internal integration tokens need manual owner action", EnvRevokeClientID, EnvRevokeClientSecret)
	}
	payload, err := json.Marshal(map[string]string{"token": secret})
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	headers := map[string]string{
		"Authorization":  "Basic " + base64.StdEncoding.EncodeToString([]byte(cid+":"+csec)),
		"Notion-Version": notionVersion,
		"Content-Type":   "application/json",
	}
	base := strings.TrimRight(apiBase, "/")
	id := revokehttp.Fingerprint(secret)

	active, err := introspect(ctx, base, headers, payload)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	if !active {
		return detectors.RevokeResult{Revoked: true, RevokedAt: time.Now().UTC(), ProviderID: id, Err: errors.New("notion: revoke: token already inactive for this app")}, nil
	}
	resp, err := revokehttp.Do(ctx, httpClient, http.MethodPost, base+"/v1/oauth/revoke", headers, bytes.NewReader(payload))
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	if resp.Status != http.StatusOK {
		return detectors.RevokeResult{}, revokehttp.StatusError("notion", resp.Status)
	}
	active, err = introspect(ctx, base, headers, payload)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	if active {
		return detectors.RevokeResult{ProviderID: id, Err: errors.New("notion: revoke: token still active after revoke")}, nil
	}
	return detectors.RevokeResult{Revoked: true, RevokedAt: time.Now().UTC(), ProviderID: id}, nil
}

func introspect(ctx context.Context, base string, headers map[string]string, payload []byte) (bool, error) {
	resp, err := revokehttp.Do(ctx, httpClient, http.MethodPost, base+"/v1/oauth/introspect", headers, bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	if resp.Status != http.StatusOK {
		return false, fmt.Errorf("notion: revoke: introspect: unexpected HTTP %d", resp.Status)
	}
	var body struct {
		Active *bool `json:"active"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil || body.Active == nil {
		return false, errors.New("notion: revoke: introspect: missing active field")
	}
	return *body.Active, nil
}

var _ detectors.Revoker = Scanner{}
