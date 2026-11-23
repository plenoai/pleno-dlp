// Package llamacloud detects LlamaCloud API keys and verifies them against
// https://api.cloud.llamaindex.ai/api/v1/projects. Format and verification follow the
// Betterleaks rule(s) llama-cloud-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package llamacloud

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.LlamaCloud,
	Keywords: []string{"llx-"},
	Pattern:  `\b(llx-[A-Za-z0-9]{44,52})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.cloud.llamaindex.ai",
		Path:    "/api/v1/projects",
		Auth:    tokenverify.Bearer(),
	},
})

func init() { detectors.Register(Detector) }
