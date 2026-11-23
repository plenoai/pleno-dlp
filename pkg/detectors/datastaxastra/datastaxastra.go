// Package datastaxastra detects DataStax Astra application tokens and verifies them against
// https://api.astra.datastax.com/v2/tokens. Format and verification follow the
// Betterleaks rule(s) datastax-astra-application-token shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package datastaxastra

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.DataStaxAstra,
	Keywords: []string{"astracs:"},
	Pattern:  `\b(AstraCS:[A-Za-z0-9]{20,}:[a-f0-9]{64}|AstraCS:[A-Za-z0-9]{20,})`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.astra.datastax.com",
		Path:    "/v2/tokens",
		Auth:    tokenverify.Bearer(),
		Invalid: []tokenverify.Rule{{Status: 401}},
	},
})

func init() { detectors.Register(Detector) }
