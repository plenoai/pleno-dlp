// Package apify detects Apify API tokens and verifies them against
// https://api.apify.com/v2/users/me. Format and verification follow the
// Betterleaks rule(s) apify-api-token shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package apify

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Apify,
	Keywords: []string{"apify_api_"},
	Pattern:  `\b(apify_api_[A-Za-z0-9]{34,38})\b`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.apify.com",
		Path:    "/v2/users/me",
		Auth:    tokenverify.Bearer(),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"id\""}},
		Invalid: []tokenverify.Rule{{Status: 401}},
	},
})

func init() { detectors.Register(Detector) }
