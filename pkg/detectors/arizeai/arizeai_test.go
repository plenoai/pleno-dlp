//go:build detector_unit

package arizeai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "abcdef0123456789ABCDEFabcdef0123456789ABcdef01234567"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.ArizeAI {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("ARIZE_API_KEY=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED_KEY=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_BareArizeNoArm guards the radius/arm-regex tightening: a
// generic high-entropy 40-80 alnum run sitting near a bare "arize" mention
// (prose, a doc link, the app.arize.com host) but with no assignment-anchor
// reference must no longer match. Previously a radius-256 strings.Contains
// over "arize" armed this shape.
func TestFromData_BareArizeNoArm(t *testing.T) {
	body := []byte("See https://app.arize.com for docs. token=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (bare arize, no assignment anchor), got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected guards the entropy floor: a 40-80 char
// alnum run with key-shaped framing but low information content (a repeated
// placeholder) must be rejected even when the arm regex is satisfied.
func TestFromData_LowEntropyRejected(t *testing.T) {
	placeholder := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 42 'a'
	body := []byte("ARIZE_API_KEY=" + placeholder)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low-entropy placeholder), got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummy {
			t.Errorf("missing bearer auth")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil || !v {
		t.Fatalf("err=%v v=%v", err, v)
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
	v, _ := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false")
	}
}
