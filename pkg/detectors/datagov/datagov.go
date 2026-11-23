// Package datagov detects api.data.gov keys and verifies them against
// https://developer.nrel.gov/api/alt-fuel-stations/v1.json. Format and verification follow the
// Betterleaks rule(s) datagov-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package datagov

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.DataGov,
	Keywords: []string{"data.gov"},
	Pattern:  `(?i)(?:data\.gov)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-Z0-9]{40})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://developer.nrel.gov",
		Path:    "/api/alt-fuel-stations/v1.json?limit=1",
		Auth:    tokenverify.Query("api_key"),
	},
})

func init() { detectors.Register(Detector) }
