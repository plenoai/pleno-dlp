//go:build detector_unit

package gcpidtoken

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// withTestServer temporarily overrides httpClient to route requests to a
// local test server and restores the original client when done.
func withTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	orig := httpClient
	httpClient = srv.Client()
	httpClient.Transport = &rewriteTransport{
		base: srv.Client().Transport,
		dest: srv.URL,
	}
	t.Cleanup(func() {
		httpClient = orig
		srv.Close()
	})
	return srv
}

// rewriteTransport rewrites every request to point at a test server URL.
type rewriteTransport struct {
	base http.RoundTripper
	dest string
}

func (rt *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Preserve query string, replace scheme+host.
	req = req.Clone(req.Context())
	req.URL.Scheme = "http"
	req.URL.Host = rt.dest[len("http://"):]
	return rt.base.RoundTrip(req)
}

func TestVerify_ValidToken(t *testing.T) {
	withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"email_verified":"true","azp":"my-client.apps.googleusercontent.com","aud":"https://service.example.com"}`)
	})

	tok := mintJWT(t, map[string]string{
		"iss": "https://accounts.google.com",
		"aud": "https://service.example.com",
	})
	ok, err := Scanner{}.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected verified=true for a 200 response")
	}
}

func TestVerify_InvalidToken(t *testing.T) {
	withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_token","error_description":"Invalid Value"}`)
	})

	tok := mintJWT(t, map[string]string{
		"iss": "https://accounts.google.com",
		"aud": "https://service.example.com",
	})
	ok, err := Scanner{}.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected verified=false for a 400 response")
	}
}

func TestVerify_MalformedJWT(t *testing.T) {
	withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Google returns 400 for malformed tokens.
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_token"}`)
	})

	ok, err := Scanner{}.Verify(context.Background(), "not-a-jwt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected verified=false for malformed JWT")
	}
}

func TestVerify_EnrichesExtraData(t *testing.T) {
	withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"email_verified":"true","azp":"my-client.apps.googleusercontent.com"}`)
	})

	tok := mintJWT(t, map[string]string{
		"iss":   "https://accounts.google.com",
		"aud":   "https://service.example.com",
		"email": "user@example.com",
	})

	res, err := Scanner{}.FromData(context.Background(), true, []byte("TOKEN="+tok))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	r := res[0]
	if !r.Verified {
		t.Fatal("expected Verified=true")
	}
	if r.ExtraData["email_verified"] != "true" {
		t.Errorf("email_verified not enriched: %v", r.ExtraData)
	}
	if r.ExtraData["azp"] != "my-client.apps.googleusercontent.com" {
		t.Errorf("azp not enriched: %v", r.ExtraData)
	}
	if r.ExtraData["iss"] != "https://accounts.google.com" {
		t.Errorf("iss claim lost: %v", r.ExtraData)
	}
}

func TestDecodeClaims_AllFields(t *testing.T) {
	tok := mintJWT(t, map[string]string{
		"iss":   "https://accounts.google.com",
		"sub":   "1234567890",
		"aud":   "https://service.example.com",
		"email": "user@example.com",
	})
	claims := decodeClaims(tok)
	want := map[string]string{
		"iss":   "https://accounts.google.com",
		"sub":   "1234567890",
		"aud":   "https://service.example.com",
		"email": "user@example.com",
	}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("claim %q = %q, want %q", k, claims[k], v)
		}
	}
}

func TestDecodeClaims_MalformedToken(t *testing.T) {
	claims := decodeClaims("not-a-jwt")
	if len(claims) != 0 {
		t.Errorf("expected empty claims for malformed token, got %v", claims)
	}
}

func TestDecodeClaims_InvalidBase64(t *testing.T) {
	claims := decodeClaims("eyJ.!!!invalid-base64!!!.eyJ")
	if len(claims) != 0 {
		t.Errorf("expected empty claims for invalid base64, got %v", claims)
	}
}
