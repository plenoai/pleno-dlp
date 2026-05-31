package azurecr

import (
	"context"
	"encoding/base64"
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

// A token whose decoded payload self-identifies as ACR.
var acrToken = makeJWT(`{"jti":"abc","sub":"client","aud":"myregistry.azurecr.io","grant_type":"refresh_token"}`)

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
