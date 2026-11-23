// Package mem0 detects Mem0 API keys and verifies them against
// https://api.mem0.ai/v3/memories/. Format and verification follow the
// Betterleaks rule(s) mem0-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package mem0

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Mem0,
	Keywords: []string{"mem0"},
	Pattern:  `(?i)(?:mem0)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(m0-[A-Za-z0-9]{24,44})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:      http.MethodPost,
		BaseURL:     "https://api.mem0.ai",
		Path:        "/v3/memories/?page=1&page_size=1",
		Auth:        tokenverify.Header("Authorization", "Token "),
		Body:        "{\"filters\":{\"user_id\":\"pleno-dlp-validation\"}}",
		ContentType: "application/json",
		Valid:       []tokenverify.Rule{{Status: 200, BodyContains: "\"results\""}},
	},
})

func init() { detectors.Register(Detector) }
