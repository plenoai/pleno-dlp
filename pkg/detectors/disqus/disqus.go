// Package disqus detects Disqus API secrets and verifies them against
// https://disqus.com/api/3.0/threads/list.json. Format and verification follow the
// Betterleaks rule(s) disqus-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package disqus

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Disqus,
	Keywords: []string{"disqus"},
	Pattern:  `(?i)(?:disqus)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-Z0-9]{64})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://disqus.com",
		Path:    "/api/3.0/threads/list.json?limit=1",
		Auth:    tokenverify.Query("api_secret"),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"code\":0"}},
	},
})

func init() { detectors.Register(Detector) }
