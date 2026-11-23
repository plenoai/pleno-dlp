// Package valtown detects Val Town API tokens and verifies them against
// https://api.val.town/v1/me. Format and verification follow the
// Betterleaks rule(s) val-town-api-token shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package valtown

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.ValTown,
	Keywords: []string{"vtwn_"},
	Pattern:  `\b(vtwn_[A-Za-z0-9_-]{20,80})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.val.town",
		Path:    "/v1/me",
		Auth:    tokenverify.Bearer(),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"id\""}},
	},
})

func init() { detectors.Register(Detector) }
