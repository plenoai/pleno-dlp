// Package polar detects Polar access token (OAuth, organization, personal)s and verifies them against
// https://api.polar.sh/v1/oauth2/userinfo. Format and verification follow the
// Betterleaks rule(s) polar-oauth-access-token, polar-organization-access-token, polar-personal-access-token shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package polar

import (
	"net/http"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Polar,
	Keywords: []string{"polar_at_", "polar_oat_", "polar_pat_"},
	Pattern:  `\b(polar_(?:at|oat|pat)_[A-Za-z0-9_-]{20,100})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.polar.sh",
		Path:    "/v1/oauth2/userinfo",
		PathFor: func(s string) string {
			if strings.HasPrefix(s, "polar_oat_") {
				return "/v1/organizations/"
			}
			return "/v1/oauth2/userinfo"
		},
		Auth:  tokenverify.Bearer(),
		Valid: []tokenverify.Rule{{Status: 200, BodyContains: "\"sub\""}, {Status: 200, BodyContains: "\"items\""}},
	},
})

func init() { detectors.Register(Detector) }
