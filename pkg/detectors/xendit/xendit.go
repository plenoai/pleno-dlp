// Package xendit detects Xendit production API keys and verifies them against
// https://api.xendit.co/balance. Format and verification follow the
// Betterleaks rule(s) xendit-production-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package xendit

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Xendit,
	Keywords: []string{"xnd_production_"},
	Pattern:  `\b(xnd_production_[A-Za-z0-9]{56,72})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.xendit.co",
		Path:    "/balance",
		Auth:    tokenverify.BasicUser(),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"balance\""}},
	},
})

func init() { detectors.Register(Detector) }
