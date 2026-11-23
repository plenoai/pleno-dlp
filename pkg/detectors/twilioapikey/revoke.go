package twilioapikey

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/revokehttp"
)

// Revoke inputs: the account that owns the key. Twilio deletes an API key
// with DELETE /2010-04-01/Accounts/{AccountSid}/Keys/{KeySid}.json,
// authenticated as the account (Auth Token) — the leaked key cannot be
// trusted to delete itself because Standard keys lack Keys access.
const (
	EnvRevokeAccountSID = "PLENO_DLP_REVOKE_TWILIO_ACCOUNT_SID"
	EnvRevokeAuthToken  = "PLENO_DLP_REVOKE_TWILIO_AUTH_TOKEN"
)

var (
	keySIDRe     = detectors.MustCompile(`^SK[0-9a-fA-F]{32}$`)
	accountSIDRe = detectors.MustCompile(`^AC[0-9a-fA-F]{32}$`)
)

// Revoke deletes the API key. secret is the key SID, optionally followed
// by ":<secret>" (the Verify form); only the SID is sent. HTTP 404 cannot
// distinguish "already deleted" from "owned by another account", so it is
// reported as unconfirmed (Revoked=false with a diagnostic).
func (Scanner) Revoke(ctx context.Context, secret string) (detectors.RevokeResult, error) {
	sid, _, _ := strings.Cut(strings.TrimSpace(secret), ":")
	if !keySIDRe.MatchString(sid) {
		return detectors.RevokeResult{}, errors.New("twilio: revoke: secret is not an API key SID (SK + 32 hex)")
	}
	acct, token := revokehttp.Env(EnvRevokeAccountSID), revokehttp.Env(EnvRevokeAuthToken)
	if acct == "" || token == "" {
		return detectors.RevokeResult{}, fmt.Errorf("twilio: revoke: %s and %s of the owning account are required", EnvRevokeAccountSID, EnvRevokeAuthToken)
	}
	if !accountSIDRe.MatchString(acct) {
		return detectors.RevokeResult{}, fmt.Errorf("twilio: revoke: %s is not an Account SID (AC + 32 hex)", EnvRevokeAccountSID)
	}
	headers := map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(acct+":"+token)),
	}
	url := strings.TrimRight(apiBase, "/") + "/2010-04-01/Accounts/" + acct + "/Keys/" + sid + ".json"
	resp, err := revokehttp.Do(ctx, httpClient, http.MethodDelete, url, headers, nil)
	if err != nil {
		return detectors.RevokeResult{}, errors.New("twilio: revoke: request failed")
	}
	switch resp.Status {
	case http.StatusNoContent, http.StatusOK:
		return detectors.RevokeResult{Revoked: true, RevokedAt: time.Now().UTC(), ProviderID: sid}, nil
	case http.StatusNotFound:
		return detectors.RevokeResult{ProviderID: sid, Err: errors.New("twilio: revoke: key not found under this account (already deleted, or owned by another account)")}, nil
	default:
		return detectors.RevokeResult{}, revokehttp.StatusError("twilio", resp.Status)
	}
}

var _ detectors.Revoker = Scanner{}
