package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func makeJWT(t *testing.T, header, claims map[string]interface{}) string {
	t.Helper()
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	return enc(hb) + "." + enc(cb) + ".sig" + enc([]byte("0123456789"))
}

func TestFromData_Positive(t *testing.T) {
	tok := makeJWT(t,
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"iss": "issuer.example", "sub": "user-123"},
	)
	res, err := Scanner{}.FromData(context.Background(), false, []byte("Authorization: Bearer "+tok))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].ExtraData["iss"] != "issuer.example" {
		t.Fatalf("iss not extracted: %+v", res[0].ExtraData)
	}
	if res[0].ExtraData["sub"] != "user-123" {
		t.Fatalf("sub not extracted: %+v", res[0].ExtraData)
	}
	if res[0].ExtraData["alg"] != "HS256" {
		t.Fatalf("alg not extracted: %+v", res[0].ExtraData)
	}
	if res[0].Verified {
		t.Fatal("JWT must never be Verified=true (no key material)")
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("not-a-jwt"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	tok := makeJWT(t, map[string]interface{}{"alg": "none"}, map[string]interface{}{"x": 1})
	r := redact(tok)
	if !strings.HasPrefix(r, "eyJ") {
		t.Fatalf("missing prefix: %q", r)
	}
	if r == tok {
		t.Fatalf("redact didn't redact")
	}
}
