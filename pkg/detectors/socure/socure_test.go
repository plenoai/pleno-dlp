//go:build detector_unit

package socure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummy is a documented-shape Socure API key: a UUID v4 (8-4-4-4-12 hex,
// version nibble 4, variant nibble in [89ab]). Source: help.socure.com RiskOS
// authentication docs. Not a real credential.
const dummy = "a182150a-363a-4f4a-9b2c-1d2e3f4a5b6c"

// fpHighEntropy is a generic 40-char high-entropy alphanumeric run that the
// previous `[A-Za-z0-9]{40,80}` regex matched but is NOT a Socure UUID key.
// It must no longer be detected even when sitting next to the keyword.
const fpHighEntropy = "abcdef0123456789ABCDEFabcdef0123456789AB"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Socure {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("SOCURE_API_KEY=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_BareKeywordNoArm guards the gate tightening: a bare "socure"
// mention near a real UUID key must no longer arm, since armRe requires
// socure[_-]?(api[_-]?)?(token|key|secret).
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("see https://developer.socure.com for docs; value " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (bare keyword should not arm), got %d", len(res))
	}
}

// TestFromData_RejectsHighEntropyNonUUID is the FP regression: a generic
// 40-char high-entropy run next to the keyword must no longer be detected —
// it is not the documented UUID v4 format.
func TestFromData_RejectsHighEntropyNonUUID(t *testing.T) {
	body := []byte("SOCURE_API_KEY=" + fpHighEntropy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (non-UUID high-entropy string), got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Errorf("missing auth header")
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
