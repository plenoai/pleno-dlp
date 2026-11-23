// Package thunderstore detects Thunderstore API tokens and verifies them against
// https://thunderstore.io/api/experimental/current-user/. Format and verification follow the
// Betterleaks rule(s) thunderstore-api-token shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package thunderstore

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Thunderstore,
	Keywords: []string{"tss_"},
	Pattern:  `\b(tss_[A-Za-z0-9_-]{20,80})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://thunderstore.io",
		Path:    "/api/experimental/current-user/",
		Auth:    tokenverify.Bearer(),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"username\""}},
	},
})

func init() { detectors.Register(Detector) }
