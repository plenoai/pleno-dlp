// Package configcat detects ConfigCat SDK keys and verifies them against
// https://cdn-global.configcat.com/configuration-files/{secret}/config_v6.json. Format and verification follow the
// Betterleaks rule(s) configcat-sdk-key, configcat-sdk-key-extended shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
//
// The legacy 22/22 form is accepted only near the configcat keyword (vicinity dispatch).
package configcat

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.ConfigCat,
	Keywords: []string{"configcat"},
	Pattern:  `\b((?:configcat-sdk-1/)?[A-Za-z0-9_-]{22}/[A-Za-z0-9_-]{22})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://cdn-global.configcat.com",
		Path:    "/configuration-files/{secret}/config_v6.json",
		Auth:    tokenverify.PathSecret(),
		Valid:   []tokenverify.Rule{{Status: 200}},
		Invalid: []tokenverify.Rule{{Status: 401}, {Status: 403}, {Status: 404}},
	},
})

func init() { detectors.Register(Detector) }
