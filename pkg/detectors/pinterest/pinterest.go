// Package pinterest detects Pinterest access tokens and verifies them against
// https://api.pinterest.com/v5/user_account. Format and verification follow the
// Betterleaks rule(s) pinterest-access-token shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package pinterest

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Pinterest,
	Keywords: []string{"pina_"},
	Pattern:  `\b(pina_[A-Za-z0-9_-]{20,200})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.pinterest.com",
		Path:    "/v5/user_account",
		Auth:    tokenverify.Bearer(),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"username\""}},
	},
})

func init() { detectors.Register(Detector) }
