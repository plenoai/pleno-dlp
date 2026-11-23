// Package cursor detects Cursor admin API keys and verifies them against
// https://api.cursor.com/v0/me. Format and verification follow the
// Betterleaks rule(s) cursor-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package cursor

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Cursor,
	Keywords: []string{"cursor"},
	Pattern:  `(?i)(?:cursor)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(key_[0-9a-f]{64})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.cursor.com",
		Path:    "/v0/me",
		Auth:    tokenverify.BasicRaw(),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"userEmail\""}},
	},
})

func init() { detectors.Register(Detector) }
