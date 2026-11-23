package gcp

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

// iamBase is overridable from tests.
var iamBase = "https://iam.googleapis.com"

// Revoke deletes the leaked service-account key through IAM
// (DELETE /v1/projects/{project}/serviceAccounts/{email}/keys/{key_id}),
// authenticated by a token minted from the key itself. secret must be the
// full key JSON: scan findings carry only client_email in Raw, so pass the
// JSON via `revoke --secret`. Deleting the key neither deletes the account
// nor invalidates short-lived tokens already issued from it.
func (Scanner) Revoke(ctx context.Context, secret string) (detectors.RevokeResult, error) {
	if secret == "" {
		return detectors.RevokeResult{}, errors.New("gcp: revoke: empty secret")
	}
	var sa serviceAccount
	if err := json.Unmarshal([]byte(secret), &sa); err != nil {
		return detectors.RevokeResult{}, errors.New("gcp: revoke: secret must be the full service-account key JSON")
	}
	if sa.ClientEmail == "" || sa.KeyID == "" || sa.PrivateKey == "" {
		return detectors.RevokeResult{}, errors.New("gcp: revoke: key JSON lacks client_email, private_key_id or private_key")
	}
	project := sa.ProjectID
	if project == "" {
		project = "-"
	}
	providerID := sa.ClientEmail + "/" + sa.KeyID
	now := time.Now().UTC()

	token, authenticated, err := exchangeToken(ctx, &sa)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	if !authenticated {
		return detectors.RevokeResult{Revoked: true, RevokedAt: now, ProviderID: providerID, Err: errors.New("gcp: revoke: key no longer authenticates (already deleted or disabled)")}, nil
	}
	target := strings.TrimRight(iamBase, "/") + "/v1/projects/" + url.PathEscape(project) +
		"/serviceAccounts/" + url.PathEscape(sa.ClientEmail) + "/keys/" + url.PathEscape(sa.KeyID)
	resp, err := revokehttp.Do(ctx, httpClient, http.MethodDelete, target,
		map[string]string{"Authorization": "Bearer " + token}, nil)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	switch resp.Status {
	case http.StatusOK, http.StatusNoContent:
		return detectors.RevokeResult{Revoked: true, RevokedAt: now, ProviderID: providerID}, nil
	case http.StatusNotFound:
		return detectors.RevokeResult{Revoked: true, RevokedAt: now, ProviderID: providerID, Err: errors.New("gcp: revoke: already deleted or never existed (HTTP 404)")}, nil
	case http.StatusForbidden:
		return detectors.RevokeResult{}, errors.New("gcp: revoke: HTTP 403 — the key lacks iam.serviceAccountKeys.delete on itself; delete it with an admin principal")
	default:
		return detectors.RevokeResult{}, revokehttp.StatusError("gcp", resp.Status)
	}
}

// exchangeToken mints an access token from the key. authenticated=false
// means the token endpoint rejected the grant (key deleted or disabled).
func exchangeToken(ctx context.Context, sa *serviceAccount) (string, bool, error) {
	jwt, err := signJWT(sa)
	if err != nil {
		return "", false, err
	}
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", jwt)
	resp, err := revokehttp.Do(ctx, httpClient, http.MethodPost, tokenURL,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, strings.NewReader(form.Encode()))
	if err != nil {
		return "", false, err
	}
	switch resp.Status {
	case http.StatusOK:
	case http.StatusBadRequest, http.StatusUnauthorized:
		return "", false, nil
	default:
		return "", false, fmt.Errorf("gcp: revoke: token exchange: unexpected HTTP %d", resp.Status)
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil || body.AccessToken == "" {
		return "", false, errors.New("gcp: revoke: token exchange: missing access_token")
	}
	return body.AccessToken, true, nil
}

var _ detectors.Revoker = Scanner{}
