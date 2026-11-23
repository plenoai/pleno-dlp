// Package upcloud detects UpCloud API tokens and verifies them against
// https://api.upcloud.com/1.3/account. Format and verification follow the
// Betterleaks rule(s) upcloud-api-token shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package upcloud

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.UpCloud,
	Keywords: []string{"ucat_"},
	Pattern:  `\b(ucat_[0-9A-Za-z]{24,32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.upcloud.com",
		Path:    "/1.3/account",
		Auth:    tokenverify.Bearer(),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"account\""}},
	},
})

func init() { detectors.Register(Detector) }
