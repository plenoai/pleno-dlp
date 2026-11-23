// Package slack maps a Slack token to its workspace identity and OAuth scopes.
package slack

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/blastradius/httpx"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Mapper implements detectors.AccessMapper for Slack bot/user tokens.
type Mapper struct {
	BaseURL string // default https://slack.com/api
	Client  *http.Client
}

var privilegedScopes = map[string]bool{
	"admin": true, "chat:write": true, "files:write": true, "channels:history": true,
	"groups:history": true, "im:history": true, "users:read.email": true, "channels:manage": true,
}

func (m Mapper) MapAccess(ctx context.Context, cred detectors.AccessCredential) (*detectors.AccessMap, error) {
	base := strings.TrimRight(m.BaseURL, "/")
	if base == "" {
		base = "https://slack.com/api"
	}
	var r struct {
		OK     bool   `json:"ok"`
		Error  string `json:"error"`
		URL    string `json:"url"`
		Team   string `json:"team"`
		TeamID string `json:"team_id"`
		User   string `json:"user"`
		UserID string `json:"user_id"`
		BotID  string `json:"bot_id"`
	}
	h, err := httpx.GetJSON(ctx, m.Client, base+"/auth.test", map[string]string{"Authorization": "Bearer " + cred.Secret}, &r)
	if err != nil {
		return nil, fmt.Errorf("slack: identity: %w", err)
	}
	if !r.OK {
		return nil, errors.New("slack: identity: " + r.Error)
	}
	am := detectors.NewAccessMap("slack")
	typ := "user"
	if r.BotID != "" {
		typ = "bot"
	}
	am.Identity = detectors.AccessIdentity{ID: r.UserID, Name: r.User, Type: typ, Account: r.TeamID}
	for _, s := range strings.Split(h.Get("X-OAuth-Scopes"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			am.Permissions = append(am.Permissions, s)
			if privilegedScopes[s] || strings.HasPrefix(s, "admin") {
				am.Privileged = true
			}
		}
	}
	if len(am.Permissions) == 0 {
		am.Limitations = append(am.Limitations, "token scopes not reported by auth.test")
	}
	am.Resources = append(am.Resources, detectors.AccessResource{Type: "workspace", Name: firstNonEmpty(r.Team, r.TeamID), Permissions: am.Permissions})
	return am, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
