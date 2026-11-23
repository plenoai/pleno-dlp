// Package retell detects Retell AI API keys and verifies them against
// https://api.retellai.com/get-concurrency. Format and verification follow the
// Betterleaks rule(s) retell-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package retell

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Retell,
	Keywords: []string{"retell"},
	Pattern:  `(?i)(?:retell)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(key_[a-f0-9]{28})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.retellai.com",
		Path:    "/get-concurrency",
		Auth:    tokenverify.Bearer(),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"concurrency_limit\""}},
	},
})

func init() { detectors.Register(Detector) }
