// Package proof detects Proof full-access API keys and verifies them against
// https://api.proof.com/v1/transactions. Format and verification follow the
// Betterleaks rule(s) proof-full-access-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
//
// Valid keys are recognised by the 422 validation error for the empty transaction body; no transaction is created.
package proof

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.Proof,
	Keywords: []string{"prf_"},
	Pattern:  `\b(prf_(?:cli_)?[A-Za-z0-9_-]{20,80})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:      http.MethodPost,
		BaseURL:     "https://api.proof.com",
		Path:        "/v1/transactions",
		Auth:        tokenverify.Header("ApiKey", ""),
		Body:        "{}",
		ContentType: "application/json",
		Valid:       []tokenverify.Rule{{Status: 422, BodyContains: "signer"}},
		Invalid:     []tokenverify.Rule{{Status: 401}},
	},
})

func init() { detectors.Register(Detector) }
