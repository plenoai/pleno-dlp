//go:build detector_unit

package marketo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummyID is a UUID v4 — the authoritative Marketo client_id shape (Adobe docs
// + provider REST-Sample-Code). dummySecret is a 32-char high-entropy
// alphanumeric, the documented client_secret shape.
const dummyID = "cdf01657-110d-4155-99a7-f986b2ff13a0"
const dummySecret = "tZPVrKiEmUDezE18yZfeaPlTJ2vKn2fw"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Marketo {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("MARKETO_CLIENT_ID=" + dummyID + "\nMARKETO_CLIENT_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
	if string(res[0].RawV2) != dummySecret {
		t.Errorf("RawV2 mismatch: %s", res[0].RawV2)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("CLIENT_ID=" + dummyID + "\nCLIENT_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_GenericHighEntropyRejected is the FP-hardening regression: a
// generic high-entropy 30-char alnum run near the word "marketo" used to match
// the old bare `[A-Za-z0-9]{24,64}` id regex. It is no longer UUID-shaped, so
// the id half cannot arm and nothing is reported.
func TestFromData_GenericHighEntropyRejected(t *testing.T) {
	// 30-char base62 noise (not a UUID) + a 32-char secret, both near "marketo".
	body := []byte("marketo notes: x9Qm2Lp7Zr4Vt8Nc1Bd6Ws3Kf5Hj plus token kP9mWq2Lz7Rt4Vx8Nc1Bd6Ws3Kf5Hj0a")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (no UUID-shaped client_id), got %d", len(res))
	}
}

// TestFromData_BareKeywordNotArmed verifies the arm-regex gate: a UUID + 32-char
// secret sitting near the bare word "marketo" (no assignment-style reference)
// must NOT arm — the bare keyword is only a prefilter, not the gate.
func TestFromData_BareKeywordNotArmed(t *testing.T) {
	body := []byte("The marketo platform overview. " + dummyID + " " + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (bare keyword, no assignment anchor), got %d", len(res))
	}
}

func TestVerify_Disabled_Default(t *testing.T) {
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false default")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false")
	}
}
