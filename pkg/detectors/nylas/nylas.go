// Package nylas detects Nylas v3 API keys and verifies them against
// https://api.us.nylas.com/v3/webhooks. Format and verification follow the
// Betterleaks rule(s) nylas-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
//
// Verification queries the US region only; EU-region keys read as invalid until region fallback lands.
package nylas

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Nylas,
	Keywords: []string{"nyk_"},
	Pattern:  `\b(nyk_[A-Za-z0-9]{67})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.us.nylas.com",
		Path:    "/v3/webhooks?limit=1",
		Auth:    tokenverify.Bearer(),
		Valid:   []tokenverify.Rule{{Status: 200}, {Status: 403}},
		Invalid: []tokenverify.Rule{{Status: 401}},
	},
})

func init() { detectors.Register(Detector) }
