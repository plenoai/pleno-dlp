// Package onepassword detects 1Password service account tokens and verifies them against
// https://events.1password.com/api/v2/auth/introspect. Format and verification follow the
// Betterleaks rule(s) 1password-service-account-token shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package onepassword

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.OnePasswordServiceAccount,
	Keywords: []string{"ops_eyj"},
	Pattern:  `\b(ops_eyJ[a-zA-Z0-9+/]{250,}={0,3})`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://events.1password.com",
		Path:    "/api/v2/auth/introspect",
		Auth:    tokenverify.Bearer(),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"features\""}},
		Invalid: []tokenverify.Rule{{Status: 401}, {Status: 403}},
	},
})

func init() { detectors.Register(Detector) }
