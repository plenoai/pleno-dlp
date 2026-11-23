// Package instantly detects Instantly API keys and verifies them against
// https://api.instantly.ai/api/v2/accounts. Format and verification follow the
// Betterleaks rule(s) instantly-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package instantly

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Instantly,
	Keywords: []string{"instantly"},
	Pattern:  `(?i)(?:instantly)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9+/]{66}==)(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.instantly.ai",
		Path:    "/api/v2/accounts?limit=1",
		Auth:    tokenverify.Bearer(),
		Valid:   []tokenverify.Rule{{Status: 200}, {Status: 402}},
		Invalid: []tokenverify.Rule{{Status: 401, BodyContains: "Invalid authorization header or API key"}},
	},
})

func init() { detectors.Register(Detector) }
