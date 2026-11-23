// Package labelbox detects Labelbox API keys and verifies them against
// https://api.labelbox.com/graphql. Format and verification follow the
// Betterleaks rule(s) labelbox-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package labelbox

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Labelbox,
	Keywords: []string{"lbx_"},
	Pattern:  `\b(lbx_[\w-]{42}[AEIMQUYcgkosw048])(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:      http.MethodPost,
		BaseURL:     "https://api.labelbox.com",
		Path:        "/graphql",
		Auth:        tokenverify.Bearer(),
		Body:        "{\"query\":\"query { user { id } }\"}",
		ContentType: "application/json",
		Valid:       []tokenverify.Rule{{Status: 200, BodyContains: "\"user\":{\"id\""}},
	},
})

func init() { detectors.Register(Detector) }
