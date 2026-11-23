// Package falai detects fal.ai API keys and verifies them against
// https://api.fal.ai/v1/models/pricing. Format and verification follow the
// Betterleaks rule(s) fal-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package falai

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.FalAI,
	Keywords: []string{"fal_key", "fal-key", "falai", "fal_ai", "fal-ai", "fal.ai", "fal_api", "fal-api"},
	Pattern:  `(?i:(?:falai|fal_ai|fal-ai|fal\.ai|fal-api|fal_api|fal_key|fal-key)(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}:[a-f0-9]{32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.fal.ai",
		Path:    "/v1/models/pricing?endpoint_id=fal-ai%2Fflux%2Fdev",
		Auth:    tokenverify.Header("Authorization", "Key "),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"prices\""}},
		Invalid: []tokenverify.Rule{{Status: 401, BodyContains: "authorization_error"}},
	},
})

func init() { detectors.Register(Detector) }
