// Package gcnotify detects GC Notify (Canadian Digital Service) API keys and verifies them against
// https://api.notification.canada.ca/v2/notifications. Format and verification follow the
// Betterleaks rule(s) canadian-digital-service-notify-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package gcnotify

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.GCNotify,
	Keywords: []string{"gcntfy-"},
	Pattern:  `(?i:\b(ApiKey-v1\s+gcntfy-[a-z0-9_]+-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.notification.canada.ca",
		Path:    "/v2/notifications",
		Auth:    tokenverify.Header("Authorization", ""),
	},
})

func init() { detectors.Register(Detector) }
