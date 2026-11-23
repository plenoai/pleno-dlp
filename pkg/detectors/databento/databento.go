// Package databento detects Databento API keys and verifies them against
// https://hist.databento.com/v0/metadata.list_datasets. Format and verification follow the
// Betterleaks rule(s) databento-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package databento

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Databento,
	Keywords: []string{"databento"},
	Pattern:  `(?i)(?:databento)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(db-[A-Za-z0-9]{29})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://hist.databento.com",
		Path:    "/v0/metadata.list_datasets",
		Auth:    tokenverify.BasicUser(),
	},
})

func init() { detectors.Register(Detector) }
