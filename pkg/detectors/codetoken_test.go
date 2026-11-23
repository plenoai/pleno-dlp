package detectors

import "testing"

func TestLooksLikeCodeToken(t *testing.T) {
	code := []string{
		"dlp/pkg/detectors/wasabi",
		"com/plenoai/pleno-dlp/pkg/detectors/fullstory",
		"rest/api/latest/currentUser.json",
		"detectors.CloudBees.String",
		"OPF_SECRET",
		"SlackUserToken",
		"JSONConfigSecret",
		"NewVerifier",
		"Betterleaks",
		"pleno-dlp",
		"context-required",
		"-authorization-token",
		"required",
		"cand",
		"pdfObjHeader.FindAllSubmatchIndex",
	}
	for _, s := range code {
		if !LooksLikeCodeToken([]byte(s)) {
			t.Errorf("LooksLikeCodeToken(%q) = false, want true", s)
		}
	}
	keys := []string{
		"9epHOqHhnXUcgYK8QanOmUQPSgX92g",
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",
		"dfff6fdfb9a145d59389542285dfa505",
		"QKHLUeWw6HxyE5cq9nujHqqX",
		"AbCdEfGhIjKlMnOpQrSt",
		"aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRva2Vu",
		"x",
		"hf" + "_abcdefghijklmnopqrstuvwxyzabcdefgh",
		"hf" + "_AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh",
	}
	for _, s := range keys {
		if LooksLikeCodeToken([]byte(s)) {
			t.Errorf("LooksLikeCodeToken(%q) = true, want false", s)
		}
	}
}

func TestAcceptsWordSecretsCoversPasswordClass(t *testing.T) {
	for _, typ := range []DetectorType{HardcodedPassword, Netrc, Postgres, MySQL, MongoDB, Redis} {
		if !AcceptsWordSecrets(typ) {
			t.Errorf("AcceptsWordSecrets(%v) = false", typ)
		}
	}
	if AcceptsWordSecrets(Bamboo) {
		t.Error("AcceptsWordSecrets(Bamboo) = true")
	}
}
