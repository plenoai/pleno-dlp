//go:build detector_unit

package snowflake

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func mintJWT(t *testing.T, claims map[string]string) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	body, _ := json.Marshal(claims)
	pl := base64.RawURLEncoding.EncodeToString(body)
	sig := base64.RawURLEncoding.EncodeToString([]byte("signature-padding-bytes"))
	return hdr + "." + pl + "." + sig
}

func TestFromData_SnowflakeIssuer(t *testing.T) {
	tok := mintJWT(t, map[string]string{
		"iss": "ACME_ACCOUNT.SCAN_USER.SHA256:abc123def456abc123def456abc123def456abc123def456abc",
		"sub": "ACME_ACCOUNT.SCAN_USER",
	})
	res, err := Scanner{}.FromData(context.Background(), false, []byte("SNOWFLAKE_JWT="+tok))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if got := res[0].ExtraData["account"]; got != "ACME_ACCOUNT" {
		t.Fatalf("account claim missing, got %q", got)
	}
	if got := res[0].ExtraData["user"]; got != "SCAN_USER" {
		t.Fatalf("user claim missing, got %q", got)
	}
}

func TestFromData_NotSnowflake(t *testing.T) {
	tok := mintJWT(t, map[string]string{
		"iss": "https://accounts.google.com",
		"sub": "111111111",
	})
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(tok))
	if len(res) != 0 {
		t.Fatalf("non-snowflake JWT must not be claimed; got %d", len(res))
	}
}

func TestSplitIss(t *testing.T) {
	a, u := splitIss("ACME.USER.SHA256:abc")
	if a != "ACME" || u != "USER" {
		t.Fatalf("split mismatch: %q %q", a, u)
	}
}
