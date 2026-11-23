// Package frameio detects Frame.io developer tokens and verifies them against
// https://api.frame.io/v2/me. Format and verification follow the
// Betterleaks rule(s) frameio-api-token shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package frameio

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.FrameIO,
	Keywords: []string{"fio-u-"},
	Pattern:  `\b(fio-u-[A-Za-z0-9_=-]{64})`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.frame.io",
		Path:    "/v2/me",
		Auth:    tokenverify.Bearer(),
		Invalid: []tokenverify.Rule{{Status: 401}},
	},
})

func init() { detectors.Register(Detector) }
