// Package ionic detects Ionic personal access tokens and verifies them against
// https://api.ionic.io/graphql. Format and verification follow the
// Betterleaks rule(s) ionic-personal-access-token shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package ionic

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Ionic,
	Keywords: []string{"ion_"},
	Pattern:  `\b(ion_[A-Za-z0-9]{42})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:      http.MethodPost,
		BaseURL:     "https://api.ionic.io",
		Path:        "/graphql",
		Auth:        tokenverify.Bearer(),
		Body:        "{\"query\":\"query ValidateToken { viewer { __typename } }\"}",
		ContentType: "application/json",
		Valid:       []tokenverify.Rule{{Status: 200, BodyContains: "\"data\":{\"viewer\":{\"__typename\":"}},
	},
})

func init() { detectors.Register(Detector) }
