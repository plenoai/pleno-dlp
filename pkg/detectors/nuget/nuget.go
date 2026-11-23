// Package nuget detects NuGet API keys and verifies them against
// https://www.nuget.org/api/v2/verifykey/pleno-dlp--nonexistent/0.0.0. Format and verification follow the
// Betterleaks rule(s) nuget-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package nuget

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.NuGet,
	Keywords: []string{"oy2"},
	Pattern:  `\b(oy2[a-p][a-z2-7]{15}[aq][a-z2-7]{25}[aeimquy4])(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://www.nuget.org",
		Path:    "/api/v2/verifykey/pleno-dlp--nonexistent/0.0.0",
		Auth:    tokenverify.Header("X-NuGet-ApiKey", ""),
		Valid:   []tokenverify.Rule{{Status: 404, BodyContains: "does not exist."}, {Status: 400}},
		Invalid: []tokenverify.Rule{{Status: 403}},
	},
})

func init() { detectors.Register(Detector) }
