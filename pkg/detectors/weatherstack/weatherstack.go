// Package weatherstack detects Weatherstack access keys and verifies them against
// https://api.weatherstack.com/current. Format and verification follow the
// Betterleaks rule(s) weatherstack-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package weatherstack

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Weatherstack,
	Keywords: []string{"weatherstack"},
	Pattern:  `(?i:(?:weatherstack(?:[_. -]*(?:api))?[_. -]*(?:secret|key|token))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-z]{32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.weatherstack.com",
		Path:    "/current?query=London",
		Auth:    tokenverify.Query("access_key"),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"location\""}, {Status: 200, BodyContains: "does not support HTTPS Encryption"}},
		Invalid: []tokenverify.Rule{{Status: 200, BodyContains: "\"error\""}, {Status: 401}},
	},
})

func init() { detectors.Register(Detector) }
