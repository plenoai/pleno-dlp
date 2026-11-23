// Package lichess detects Lichess personal access tokens and verifies them against
// https://lichess.org/api/account. Format and verification follow the
// Betterleaks rule(s) lichess-personal-access-token shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package lichess

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Lichess,
	Keywords: []string{"lip_"},
	Pattern:  `\b(lip_[A-Za-z0-9_]{16,60})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://lichess.org",
		Path:    "/api/account",
		Auth:    tokenverify.Bearer(),
	},
})

func init() { detectors.Register(Detector) }
