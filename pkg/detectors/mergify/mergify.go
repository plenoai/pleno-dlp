// Package mergify detects Mergify application keys and verifies them against
// https://api.mergify.com/v1/application. Format and verification follow the
// Betterleaks rule(s) mergify-application-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package mergify

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Mergify,
	Keywords: []string{"mergify_application_key_"},
	Pattern:  `\b(mergify_application_key_[A-Za-z0-9_-]{40,200})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.mergify.com",
		Path:    "/v1/application",
		Auth:    tokenverify.Bearer(),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"scope\""}},
	},
})

func init() { detectors.Register(Detector) }
