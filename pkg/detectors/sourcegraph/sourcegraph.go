// Package sourcegraph detects Sourcegraph access tokens and verifies them against
// https://sourcegraph.com/.api/graphql. Format and verification follow the
// Betterleaks rule(s) sourcegraph-access-token shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
//
// Verifies against sourcegraph.com; tokens minted by self-hosted instances read as invalid.
package sourcegraph

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Sourcegraph,
	Keywords: []string{"sgp_"},
	Pattern:  `(?i)\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:      http.MethodPost,
		BaseURL:     "https://sourcegraph.com",
		Path:        "/.api/graphql",
		Auth:        tokenverify.Header("Authorization", "token "),
		Body:        "{\"query\":\"query ValidateToken { currentUser { id } }\"}",
		ContentType: "application/json",
		Valid:       []tokenverify.Rule{{Status: 200, BodyContains: "\"currentUser\":{\"id\""}},
	},
})

func init() { detectors.Register(Detector) }
