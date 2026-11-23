// Package zuplo detects Zuplo consumer API keys and verifies them against
// https://dev.zuplo.com/v1/who-am-i. Format and verification follow the
// Betterleaks rule(s) zuplo-consumer-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package zuplo

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Zuplo,
	Keywords: []string{"zpka_"},
	Pattern:  `\b(zpka_[a-z0-9]{32}_[0-9a-f]{8})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://dev.zuplo.com",
		Path:    "/v1/who-am-i",
		Auth:    tokenverify.Bearer(),
	},
})

func init() { detectors.Register(Detector) }
