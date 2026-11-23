// Package cloudsmith detects Cloudsmith API keys and verifies them against
// https://api.cloudsmith.io/user/self/. Format and verification follow the
// Betterleaks rule(s) cloudsmith-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package cloudsmith

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Cloudsmith,
	Keywords: []string{"csa_"},
	Pattern:  `\b(csa_[a-f0-9]{30}[A-Za-z0-9]{6})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.cloudsmith.io",
		Path:    "/user/self/",
		Auth:    tokenverify.Bearer(),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"authenticated\": true"}, {Status: 200, BodyContains: "\"authenticated\":true"}},
		Invalid: []tokenverify.Rule{{Status: 401}, {Status: 403}, {Status: 200, BodyContains: "\"authenticated\": false"}, {Status: 200, BodyContains: "\"authenticated\":false"}},
	},
})

func init() { detectors.Register(Detector) }
