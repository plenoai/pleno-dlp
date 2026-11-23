// Package rubygems detects RubyGems API keys and verifies them against
// https://rubygems.org/api/v1/gems.json. Format and verification follow the
// Betterleaks rule(s) rubygems-api-token shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
//
// HTTP 403 without "invalid API key" is a live key lacking the index scope (valid); 403 with it is a deleted key.
package rubygems

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.RubyGems,
	Keywords: []string{"rubygems_"},
	Pattern:  `\b(rubygems_[a-f0-9]{48})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://rubygems.org",
		Path:    "/api/v1/gems.json",
		Auth:    tokenverify.Header("Authorization", ""),
		Headers: map[string]string{"Accept": "application/json"},
		Valid:   []tokenverify.Rule{{Status: 200}, {Status: 403, BodyNotContains: "invalid API key"}},
		Invalid: []tokenverify.Rule{{Status: 401}, {Status: 403, BodyContains: "invalid API key"}},
	},
})

func init() { detectors.Register(Detector) }
