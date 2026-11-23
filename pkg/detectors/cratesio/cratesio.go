// Package cratesio detects crates.io API tokens and verifies them against
// https://crates.io/api/v1/crates. Format and verification follow the
// Betterleaks rule(s) crates-io-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package cratesio

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.CratesIO,
	Keywords: []string{"crates"},
	Pattern:  `(?i)(?:crates(?:[_.-]?io)?)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(cio[A-Za-z0-9]{32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://crates.io",
		Path:    "/api/v1/crates?following=1&per_page=1",
		Auth:    tokenverify.Header("Authorization", ""),
		Headers: map[string]string{"Accept": "application/json", "User-Agent": "pleno-dlp-verify/1"},
		Valid:   []tokenverify.Rule{{Status: 200}, {Status: 403, BodyContains: "this token does not have the required permissions to perform this action"}},
		Invalid: []tokenverify.Rule{{Status: 403, BodyContains: "authentication failed"}},
	},
})

func init() { detectors.Register(Detector) }
