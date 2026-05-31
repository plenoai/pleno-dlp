package wiz

import (
	"context"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// A genuine-shaped Wiz OAuth2 access token: header carries alg=RS256, payload
// iss=auth.app.wiz.io, all three segments are high-entropy base64url.
const wizToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ind6LTdIcTMiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJ3aXotYXBpIiwiZXhwIjoxOTAwMDAwMDAwLCJpc3MiOiJhdXRoLmFwcC53aXouaW8iLCJzdWIiOiJzYXx4OWYyIn0.c2lnLTlmODZkMDgxODg0YzdkNjU5YTJmZWFhMGM1NWFkMDE1YTNiZjRmMWI"

// Foreign-IdP JWTs that share the dotted shape but belong elsewhere.
const googleIDToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImdwLTlLeDIiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJwcm9qIiwiZXhwIjoxOTAwMDAwMDAwLCJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vcHJvaiIsInN1YiI6InUxMjM0NSJ9.Z3NpZy05Zjg2ZDA4MTg4NGM3ZDY1OWEyZmVhYTBjNTVhZDAxNWNhZmU"

const auth0Token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImEwLTRMbTgiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJhcGkuZXhhbXBsZS5jb20iLCJleHAiOjE5MDAwMDAwMDAsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8YWJjIn0.YXNpZy05Zjg2ZDA4MTg4NGM3ZDY1OWEyZmVhYTBjNTVhZDAxNWJlZWY"

// Low-entropy dotted placeholder — matched the old regex, suppressed now.
var lowEntropyPlaceholder = strings.Repeat("a", 60) + "." + strings.Repeat("b", 80) + "." + strings.Repeat("c", 60)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Wiz {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

// TP: a real-shaped Wiz token annotated with a Wiz keyword is still detected.
func TestFromData_TruePositive(t *testing.T) {
	body := []byte("# auth.wiz.io service account\nWIZ_TOKEN=" + wizToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 Wiz token, got %d", len(res))
	}
	if string(res[0].Raw) != wizToken {
		t.Fatalf("raw mismatch")
	}
}

// FP suppressed: low-entropy aaaa.bbbb.cccc placeholder near a wiz.io mention.
func TestFromData_SuppressLowEntropyPlaceholder(t *testing.T) {
	body := []byte("see https://wiz.io docs, token = " + lowEntropyPlaceholder)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected low-entropy placeholder suppressed, got %d", len(res))
	}
}

// FP suppressed: a genuine Google/Firebase ID token sitting next to a wiz.io
// mention must not be attributed to Wiz.
func TestFromData_SuppressForeignGoogleToken(t *testing.T) {
	body := []byte("# config for wiz.io integration\nID_TOKEN=" + googleIDToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected Google ID token suppressed, got %d", len(res))
	}
}

// FP suppressed: an Auth0 access token near a wiz_client_id example value.
func TestFromData_SuppressForeignAuth0Token(t *testing.T) {
	body := []byte("wiz_client_id=example-id\n# auth0 fixture\naccess_token=" + auth0Token)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected Auth0 token suppressed, got %d", len(res))
	}
}

// Vicinity gate: a real Wiz token with no nearby Wiz keyword is not emitted.
func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+wizToken))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

// Tightened radius: keyword beyond 96 bytes no longer attaches.
func TestFromData_KeywordTooFar(t *testing.T) {
	body := []byte("wiz.io" + strings.Repeat(" ", 120) + wizToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 when keyword beyond radius, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("wiz.io " + wizToken + "\nwiz.io " + wizToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestFromData_NoSegments(t *testing.T) {
	short := strings.Repeat("a", 60)
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("wiz_io "+short))
	if len(res) != 0 {
		t.Fatalf("expected 0 for non-JWT shape, got %d", len(res))
	}
}

func TestRedactShort(t *testing.T) {
	if got := redact("abc"); got != "abc" {
		t.Fatalf("redact passthrough mismatch: %s", got)
	}
}
