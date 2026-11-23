// Package infomaniak detects Infomaniak API tokens and verifies them against
// https://api.infomaniak.com/1/profile. Format and verification follow the
// Betterleaks rule(s) infomaniak-api-token shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package infomaniak

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Infomaniak,
	Keywords: []string{"infomaniak"},
	Pattern:  `(?i)(?:infomaniak)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9_\-]{60,100})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.infomaniak.com",
		Path:    "/1/profile",
		Auth:    tokenverify.Bearer(),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"result\""}},
	},
})

func init() { detectors.Register(Detector) }
