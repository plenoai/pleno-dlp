//go:build detector_unit

package woodpecker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummyToken is a dummy-shaped HS256 JWT (eyJ header . payload . signature),
// the authoritative Woodpecker CI token format. Not a real token.
const dummyToken = "eyJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoidXNlciIsInRleHQiOiJhbGljZSJ9.dGhpc2lzbm90YXJlYWxzaWduYXR1cmVhdGFsbA"

// fpToken is a generic high-entropy 40-char alphanumeric run with no JWT
// structure. The old `[A-Za-z0-9]{32,64}` regex matched it; the JWT-anchored
// regex must not, even sitting right next to the woodpecker keyword.
const fpToken = "abcdef0123456789ABCDEF0123456789abcdefAB"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Woodpecker {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("WOODPECKER_TOKEN=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("TOKEN=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without woodpecker keyword, got %d", len(res))
	}
}

// TestFromData_RejectsGenericHighEntropy is the FP regression: a generic
// high-entropy alphanumeric run next to the woodpecker keyword must no longer
// match now that the regex is anchored on the JWT structure.
func TestFromData_RejectsGenericHighEntropy(t *testing.T) {
	body := []byte("WOODPECKER_TOKEN=" + fpToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for generic high-entropy non-JWT run, got %d", len(res))
	}
}

// TestFromData_RejectsFarKeyword guards the radius tightening: a JWT more
// than 64 bytes from the keyword arm must not match.
func TestFromData_RejectsFarKeyword(t *testing.T) {
	body := []byte("woodpecker_token mentioned here, then " + strings.Repeat("x", 80) + " " + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for JWT far from keyword, got %d", len(res))
	}
}

func TestVerify_Disabled(t *testing.T) {
	old := apiBase
	apiBase = ""
	defer func() { apiBase = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummyToken)
	if v {
		t.Fatal("expected verified=false when apiBase empty")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummyToken {
			t.Errorf("auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyToken)
	if err != nil || !v {
		t.Fatalf("expected verified=true: err=%v v=%v", err, v)
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummyToken)
	if v {
		t.Fatal("expected verified=false")
	}
}
