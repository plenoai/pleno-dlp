// Package lighton detects LightOn Paradigm API keys and verifies them against
// https://paradigm.lighton.ai/api/v2/models. Format and verification follow the
// Betterleaks rule(s) lighton-paradigm-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package lighton

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.LightOn,
	Keywords: []string{"lighton", "paradigm"},
	Pattern:  `(?i)(?:lighton|paradigm)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9_\-]{40,80})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://paradigm.lighton.ai",
		Path:    "/api/v2/models",
		Auth:    tokenverify.Bearer(),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"object\""}},
	},
})

func init() { detectors.Register(Detector) }
