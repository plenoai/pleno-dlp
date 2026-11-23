// Package influxdb detects InfluxDB Cloud API tokens and verifies them against
// https://us-east-1-1.aws.cloud2.influxdata.com/api/v2/orgs. Format and verification follow the
// Betterleaks rule(s) influxdb-api-token shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
//
// Verification targets the us-east-1 AWS cloud region; tokens for other regions or self-hosted servers return 401 there and read as invalid.
package influxdb

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.InfluxDB,
	Keywords: []string{"influx"},
	Pattern:  `(?i)(?:\binflux(?:db)?\b(?:.|[\n\r]){0,64}?\b(?:token|api[_-]?key)\b(?:.|[\n\r]){0,32}?)[=:"'\s]{1,8}([A-Za-z0-9+/=_-]{88,})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://us-east-1-1.aws.cloud2.influxdata.com",
		Path:    "/api/v2/orgs",
		Auth:    tokenverify.Header("Authorization", "Token "),
	},
})

func init() { detectors.Register(Detector) }
