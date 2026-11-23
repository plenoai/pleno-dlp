// Package samsara detects Samsara API tokens and verifies them against
// https://api.samsara.com/fleet/vehicles. Format and verification follow the
// Betterleaks rule(s) samsara-api-token shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package samsara

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Samsara,
	Keywords: []string{"samsara_api_"},
	Pattern:  `\b(samsara_api_[A-Za-z0-9]{26,32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.samsara.com",
		Path:    "/fleet/vehicles",
		Auth:    tokenverify.Bearer(),
	},
})

func init() { detectors.Register(Detector) }
