// Package bitly detects Bitly access tokens and verifies them against
// https://api-ssl.bitly.com/v4/user. Format and verification follow the
// Betterleaks rule(s) bitly-access-token shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package bitly

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Bitly,
	Keywords: []string{"bitly"},
	Pattern:  `(?i)\bbitly(?:.|[\n\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\n\r]){0,32}?\b([a-f0-9]{40})\b`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api-ssl.bitly.com",
		Path:    "/v4/user",
		Auth:    tokenverify.Bearer(),
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"login\""}},
		Invalid: []tokenverify.Rule{{Status: 401}, {Status: 403}},
	},
})

func init() { detectors.Register(Detector) }
