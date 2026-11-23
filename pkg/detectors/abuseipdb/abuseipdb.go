// Package abuseipdb detects AbuseIPDB API keys and verifies them against
// https://api.abuseipdb.com/api/v2/check. Format and verification follow the
// Betterleaks rule(s) abuseipdb-api-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package abuseipdb

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.AbuseIPDB,
	Keywords: []string{"abuseipdb"},
	Pattern:  `(?i)(?:abuseipdb)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{80})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.abuseipdb.com",
		Path:    "/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1",
		Auth:    tokenverify.Header("Key", ""),
		Headers: map[string]string{"Accept": "application/json"},
		Valid:   []tokenverify.Rule{{Status: 200, BodyContains: "\"ipAddress\""}},
		Invalid: []tokenverify.Rule{{Status: 401}},
	},
})

func init() { detectors.Register(Detector) }
