// Package upstage detects Upstage API keys and verifies them against
// https://api.upstage.ai/v1/models. Format and verification follow the
// Betterleaks rule(s) upstage-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package upstage

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Upstage,
	Keywords: []string{"upstage"},
	Pattern:  `(?i)(?:upstage)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{40,50})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.upstage.ai",
		Path:    "/v1/models",
		Auth:    tokenverify.Bearer(),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"data\""}},
	},
})

func init() { detectors.Register(Detector) }
