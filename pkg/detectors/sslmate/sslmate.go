// Package sslmate detects SSLMate API keys and verifies them against
// https://sslmate.com/api/v2/certs/example.com. Format and verification follow the
// Betterleaks rule(s) sslmate-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package sslmate

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.SSLMate,
	Keywords: []string{"sslmate"},
	Pattern:  `(?i:(?:sslmate(?:[_. -]*(?:api))?[_. -]*(?:secret|key|token))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{36})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://sslmate.com",
		Path:    "/api/v2/certs/example.com",
		Auth:    tokenverify.BasicUser(),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"exists\""}},
	},
})

func init() { detectors.Register(Detector) }
