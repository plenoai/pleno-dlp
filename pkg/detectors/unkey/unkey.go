// Package unkey detects Unkey root keys and verifies them against
// https://api.unkey.com/v2/keys.verifyKey. Format and verification follow the
// Betterleaks rule(s) unkey-root-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package unkey

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Unkey,
	Keywords: []string{"unkey_"},
	Pattern:  `\b(unkey_[A-Za-z0-9]{20,32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:      http.MethodPost,
		BaseURL:     "https://api.unkey.com",
		Path:        "/v2/keys.verifyKey",
		Auth:        tokenverify.Bearer(),
		Body:        "{\"key\":\"pleno_dlp_validation_key\"}",
		ContentType: "application/json",
		Valid:       []tokenverify.Rule{{Status: 200, BodyContains: "\"data\""}},
		Invalid:     []tokenverify.Rule{{Status: 401}},
	},
})

func init() { detectors.Register(Detector) }
