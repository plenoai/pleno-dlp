package azurecr

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// makeJWT builds a JWT-shaped token with the given JSON payload and a
// high-entropy signature so it survives the entropy gate.
func makeJWT(payloadJSON string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	// Realistic-looking high-entropy signature (not a real signature).
	sig := "Qm9Hc3RfZW50cm9weV9zaWduYXR1cmVfM2Y4YTJiN2M5ZDFlNGY2YThjMGI"
	return header + "." + payload + "." + sig
}

// A token whose decoded payload self-identifies as ACR (refresh token shape).
var acrToken = makeJWT(`{"jti":"abc","sub":"client","aud":"myregistry.azurecr.io","grant_type":"refresh_token"}`)

// An ACR access token (no grant_type claim).
var acrAccessToken = makeJWT(`{"jti":"def","sub":"client","aud":"myregistry.azurecr.io","permissions":{"actions":["read"]}}`)

// An Azure AD access token shape: points at login.microsoftonline.com / Graph.
var azureADToken = makeJWT(`{"aud":"https://graph.microsoft.com","iss":"https://sts.windows.net/tenant/","appid":"x"}`)

// A generic OIDC/CI JWT that references no ACR host at all.
var oidcToken = makeJWT(`{"aud":"https://github.com/org/repo","iss":"https://token.actions.githubusercontent.com"}`)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.AzureContainerRegistry {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

// True positive: ACR token next to its host, payload self-identifies as ACR.
func TestFromData_TruePositive_AzurecrHost(t *testing.T) {
	body := []byte("docker login myregistry.azurecr.io -p " + acrToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 true positive, got %d", len(res))
	}
}

// True positive: acr_refresh keyword + ACR payload.
func TestFromData_TruePositive_AcrRefreshKeyword(t *testing.T) {
	body := []byte("acr_refresh_token=" + acrToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 true positive, got %d", len(res))
	}
}

// FP suppressed: an Azure AD bearer token logged near an azurecr.io host.
// Belongs to AzureAD, not ACR — must be skipped despite the nearby keyword.
func TestFromData_FP_AzureADTokenNearAzurecrHost(t *testing.T) {
	body := []byte("registry: myregistry.azurecr.io\nbearer " + azureADToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected Azure AD token suppressed, got %d", len(res))
	}
}

// FP suppressed: a CI/OIDC JWT in a docker/login-action step near an ACR host.
// Payload references no azurecr.io host, so it must not be flagged.
func TestFromData_FP_OIDCTokenInWorkflow(t *testing.T) {
	body := []byte("- uses: docker/login-action\n  registry: myregistry.azurecr.io\n  token: " + oidcToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected OIDC token suppressed, got %d", len(res))
	}
}

// FP suppressed: a low-entropy placeholder/template JWT near an acr_ keyword.
func TestFromData_FP_LowEntropyPlaceholder(t *testing.T) {
	// Payload self-identifies as ACR but signature is a repeated low-entropy run.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"x.azurecr.io"}`))
	placeholder := header + "." + payload + "." + strings.Repeat("a", 40)
	body := []byte("acr_token=" + placeholder)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected low-entropy placeholder suppressed, got %d", len(res))
	}
}

// FP suppressed: no context keyword at all.
func TestFromData_FP_NoKeyword(t *testing.T) {
	body := []byte("token=" + acrToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

// FP suppressed: keyword is far away (beyond the tightened 64-byte radius).
func TestFromData_FP_KeywordTooFar(t *testing.T) {
	body := []byte("myregistry.azurecr.io" + strings.Repeat(" ", 200) + acrToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 when keyword beyond radius, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("azurecr=" + acrToken + "\nazurecr=" + acrToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestFromData_NotJWTShaped(t *testing.T) {
	body := []byte("azurecr=" + strings.Repeat("a", 50))
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for non-JWT shape, got %d", len(res))
	}
}

// --- extractACRHost tests ---

func TestExtractACRHost_RefreshToken(t *testing.T) {
	host, ok := extractACRHost(acrToken)
	if !ok {
		t.Fatal("expected host extraction to succeed")
	}
	if host != "myregistry.azurecr.io" {
		t.Fatalf("expected myregistry.azurecr.io, got %s", host)
	}
}

func TestExtractACRHost_AccessToken(t *testing.T) {
	host, ok := extractACRHost(acrAccessToken)
	if !ok {
		t.Fatal("expected host extraction to succeed")
	}
	if host != "myregistry.azurecr.io" {
		t.Fatalf("expected myregistry.azurecr.io, got %s", host)
	}
}

func TestExtractACRHost_NoACRHost(t *testing.T) {
	_, ok := extractACRHost(oidcToken)
	if ok {
		t.Fatal("expected extraction to fail for non-ACR token")
	}
}

func TestExtractACRHost_NotJWT(t *testing.T) {
	_, ok := extractACRHost("not-a-jwt")
	if ok {
		t.Fatal("expected extraction to fail for non-JWT input")
	}
}

func TestExtractACRHost_HyphenatedRegistry(t *testing.T) {
	token := makeJWT(`{"aud":"my-cool-registry.azurecr.io"}`)
	host, ok := extractACRHost(token)
	if !ok {
		t.Fatal("expected host extraction to succeed for hyphenated registry")
	}
	if host != "my-cool-registry.azurecr.io" {
		t.Fatalf("expected my-cool-registry.azurecr.io, got %s", host)
	}
}

// --- isRefreshToken tests ---

func TestIsRefreshToken_True(t *testing.T) {
	if !isRefreshToken(acrToken) {
		t.Fatal("expected acrToken to be classified as refresh token")
	}
}

func TestIsRefreshToken_False(t *testing.T) {
	if isRefreshToken(acrAccessToken) {
		t.Fatal("expected acrAccessToken to not be classified as refresh token")
	}
}

func TestIsRefreshToken_NotJWT(t *testing.T) {
	if isRefreshToken("not-a-jwt") {
		t.Fatal("expected non-JWT to return false")
	}
}

// --- FromData with verify (httptest) ---

func TestFromData_ExtraDataRegistry(t *testing.T) {
	body := []byte("docker login myregistry.azurecr.io -p " + acrToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	if res[0].ExtraData["registry"] != "myregistry.azurecr.io" {
		t.Fatalf("expected registry=myregistry.azurecr.io, got %s", res[0].ExtraData["registry"])
	}
}

// TestVerify_AccessToken_OK tests the access-token verify path against a
// local httptest server that returns 200 on /v2/.
func TestVerify_AccessToken_OK(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" && r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	// Override httpClient for the test.
	origClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = origClient }()

	// Build a token whose payload references the test server's host.
	host := strings.TrimPrefix(srv.URL, "https://")
	// The test server uses 127.0.0.1:<port> which doesn't match azurecrHostRe,
	// so we call verifyAccessToken directly.
	verified, err := verifyAccessToken(context.Background(), host, "fake-bearer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Fatal("expected verified=true for 200 response")
	}
}

// TestVerify_AccessToken_Unauthorized tests that a 401 response yields
// verified=false.
func TestVerify_AccessToken_Unauthorized(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	origClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = origClient }()

	host := strings.TrimPrefix(srv.URL, "https://")
	verified, err := verifyAccessToken(context.Background(), host, "bad-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified {
		t.Fatal("expected verified=false for 401 response")
	}
}

// TestVerify_RefreshToken_OK tests the refresh-token verify path against a
// local httptest server that returns a valid access_token.
func TestVerify_RefreshToken_OK(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" && r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "grant_type=refresh_token") {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"access_token": "new-access-token",
				})
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	origClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = origClient }()

	host := strings.TrimPrefix(srv.URL, "https://")
	verified, err := verifyRefreshToken(context.Background(), host, "fake-refresh-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Fatal("expected verified=true for successful refresh exchange")
	}
}

// TestVerify_RefreshToken_Rejected tests that a 401 from the oauth2/token
// endpoint yields verified=false.
func TestVerify_RefreshToken_Rejected(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	origClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = origClient }()

	host := strings.TrimPrefix(srv.URL, "https://")
	verified, err := verifyRefreshToken(context.Background(), host, "bad-refresh-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified {
		t.Fatal("expected verified=false for 401 response")
	}
}

// TestVerify_NoHost tests that Verify returns (false, nil) when the token
// payload does not contain an ACR host.
func TestVerify_NoHost(t *testing.T) {
	verified, err := Scanner{}.Verify(context.Background(), oidcToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified {
		t.Fatal("expected verified=false when no ACR host in payload")
	}
}
