// Package bravesearch detects Brave Search API keys and verifies them against
// https://api.search.brave.com/res/v1/web/search. Format and verification follow the
// Betterleaks rule(s) brave-search-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package bravesearch

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.BraveSearch,
	Keywords: []string{"bsa"},
	Pattern:  `\b(BSA[A-Za-z0-9_-]{24,40})\b`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.search.brave.com",
		Path:    "/res/v1/web/search?q=pleno&count=1",
		Auth:    tokenverify.Header("X-Subscription-Token", ""),
		Headers: map[string]string{"Accept": "application/json"},
	},
})

func init() { detectors.Register(Detector) }
