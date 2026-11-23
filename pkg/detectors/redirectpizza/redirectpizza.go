// Package redirectpizza detects redirect.pizza API tokens and verifies them against
// https://redirect.pizza/api/v1/domains. Format and verification follow the
// Betterleaks rule(s) redirect-pizza-api-token shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package redirectpizza

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.RedirectPizza,
	Keywords: []string{"rpa_"},
	Pattern:  `\b(rpa_[A-Za-z0-9]{30})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://redirect.pizza",
		Path:    "/api/v1/domains",
		Auth:    tokenverify.Bearer(),
	},
})

func init() { detectors.Register(Detector) }
