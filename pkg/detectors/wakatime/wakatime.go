// Package wakatime detects WakaTime API keys and verifies them against
// https://api.wakatime.com/api/v1/users/current. Format and verification follow the
// Betterleaks rule(s) wakatime-api-key (both forms) shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package wakatime

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.WakaTime,
	Keywords: []string{"waka"},
	Pattern:  `(?i)(?:\b(waka_[a-z0-9]{36,64})|(?:waka[_. -]?time(?:[_. -]*(?:api))?[_. -]*(?:secret|key|token))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}))(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.wakatime.com",
		Path:    "/api/v1/users/current",
		Auth:    tokenverify.Query("api_key"),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"data\""}},
	},
})

func init() { detectors.Register(Detector) }
