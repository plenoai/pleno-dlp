// Package midtrans detects Midtrans production server/client keys and verifies them against
// https://api.midtrans.com/v2/pleno-dlp-validation-nonexistent/status. Format and verification follow the
// Betterleaks rule(s) midtrans-production-server-client-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package midtrans

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Midtrans,
	Keywords: []string{"mid-server-", "mid-client-"},
	Pattern:  `\b(Mid-(?:server|client)-[A-Za-z0-9_]{10,20})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.midtrans.com",
		Path:    "/v2/pleno-dlp-validation-nonexistent/status",
		Auth:    tokenverify.BasicUser(),
		Valid:   []tokenverify.Rule{{Status: 200}, {Status: 404, BodyContains: "The requested resource is not found"}},
	},
})

func init() { detectors.Register(Detector) }
