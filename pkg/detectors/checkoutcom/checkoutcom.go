// Package checkoutcom detects Checkout.com secret keys and verifies them against
// https://api.checkout.com/workflows. Format and verification follow the
// Betterleaks rule(s) checkout-secret-key shipped in kingfisher's catalog
// (docs/kingfisher-parity.md).
package checkoutcom

import (
	"net/http"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Detector is the registered scanner.
var Detector = tokenverify.New(tokenverify.Spec{
	Type:     detectors.CheckoutCom,
	Keywords: []string{"checkout"},
	Pattern:  `(?i)(?:checkout)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(sk_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:\\?['"\x60]|[\s;]|\\[nr]|$)`,
	Verify: tokenverify.Request{
		Method:  http.MethodGet,
		BaseURL: "https://api.checkout.com",
		Path:    "/workflows",
		Auth:    tokenverify.Bearer(),
	},
})

func init() { detectors.Register(Detector) }
