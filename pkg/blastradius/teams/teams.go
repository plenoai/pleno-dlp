// Package teams maps a Microsoft Teams incoming-webhook URL passively: the
// URL itself encodes the tenant and webhook identity, so no request is sent
// (posting to the webhook would publish a message to the channel).
package teams

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Mapper implements detectors.AccessMapper for Teams webhook URLs.
type Mapper struct{}

// MapAccess parses the webhook URL in cred.Secret without network access.
func (Mapper) MapAccess(_ context.Context, cred detectors.AccessCredential) (*detectors.AccessMap, error) {
	u, err := url.Parse(strings.TrimSpace(cred.Secret))
	if err != nil || u.Scheme != "https" || u.User != nil {
		return nil, errors.New("teams: not an https webhook URL")
	}
	host := strings.ToLower(u.Hostname())
	var prefix, kind string
	switch {
	case strings.HasSuffix(host, ".webhook.office.com") && strings.HasPrefix(u.Path, "/webhookb2/"):
		prefix, kind = "/webhookb2/", "workflow_webhook"
	case (host == "outlook.office.com" || strings.HasSuffix(host, ".webhook.office.com")) && strings.HasPrefix(u.Path, "/webhook/"):
		prefix, kind = "/webhook/", "legacy_webhook"
	default:
		return nil, errors.New("teams: URL does not have a Microsoft Teams webhook origin")
	}
	segs := strings.Split(strings.TrimPrefix(u.Path, prefix), "/")
	webhookID, tenant, _ := strings.Cut(segs[0], "@")
	if webhookID == "" {
		return nil, errors.New("teams: webhook id missing")
	}
	am := detectors.NewAccessMap("microsoft-teams")
	am.Identity = detectors.AccessIdentity{ID: webhookID, Type: kind, Account: tenant}
	if tenant == "" && len(segs) > 1 {
		am.Identity.Account = segs[1]
	}
	am.Permissions = []string{"channel:post_message"}
	am.Resources = []detectors.AccessResource{{Type: "channel_webhook", Name: strings.TrimSuffix(host, ".webhook.office.com"), Permissions: []string{"post_message"}}}
	am.Limitations = []string{"mapped passively from the URL; the target channel and team are not resolvable without posting"}
	return am, nil
}
