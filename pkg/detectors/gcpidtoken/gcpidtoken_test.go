package gcpidtoken

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func mintJWT(t *testing.T, claims map[string]string) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	pl := base64.RawURLEncoding.EncodeToString(body)
	sig := base64.RawURLEncoding.EncodeToString([]byte("signature-bytes-padding"))
	return hdr + "." + pl + "." + sig
}

func TestFromData_GoogleIssuer(t *testing.T) {
	tok := mintJWT(t, map[string]string{
		"iss":   "https://accounts.google.com",
		"aud":   "https://my-service.example.com",
		"email": "scanner@example.iam.gserviceaccount.com",
	})
	res, err := Scanner{}.FromData(context.Background(), false, []byte("ID_TOKEN="+tok))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].ExtraData["iss"] != "https://accounts.google.com" {
		t.Fatalf("iss claim missing: %v", res[0].ExtraData)
	}
	if res[0].ExtraData["aud"] != "https://my-service.example.com" {
		t.Fatalf("aud claim missing")
	}
}

func TestFromData_ServiceAccountIssuer(t *testing.T) {
	tok := mintJWT(t, map[string]string{
		"iss": "scanner@example.iam.gserviceaccount.com",
		"aud": "https://my-service.example.com",
	})
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(tok))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_NotGoogle(t *testing.T) {
	tok := mintJWT(t, map[string]string{
		"iss": "https://login.microsoftonline.com/abc",
		"aud": "api://something",
	})
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(tok))
	if len(res) != 0 {
		t.Fatalf("non-Google issuer must not be claimed; got %d", len(res))
	}
}
