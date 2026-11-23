// Package cartesia detects Cartesia API keys and verifies them against
// https://api.cartesia.ai/voices. Format and verification follow the
// Betterleaks rule(s) cartesia-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package cartesia

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Cartesia,
	Keywords: []string{"sk_car_"},
	Pattern:  `\b(sk_car_[A-Za-z0-9_]{20})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.cartesia.ai",
		Path:    "/voices?limit=1",
		Auth:    tokenverify.Bearer(),
		Headers: map[string]string{"Cartesia-Version": "2025-04-16"},
		Invalid: []tokenverify.Rule{{Status: 401}},
	},
})

func init() { detectors.Register(Detector) }
