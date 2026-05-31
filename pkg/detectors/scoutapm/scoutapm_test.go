package scoutapm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyAgent = "abcdEFGH12345678"
	dummyAPI   = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.ScoutAPM {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("scoutapm_agent_key=" + dummyAgent + "\nscoutapm_api_key=" + dummyAPI)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if string(res[0].Raw) != dummyAgent {
		t.Fatalf("Raw should carry agent key, got %q", res[0].Raw)
	}
	if string(res[0].RawV2) != dummyAPI {
		t.Fatalf("RawV2 should carry api key, got %q", res[0].RawV2)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("agent=" + dummyAgent + "\napi=" + dummyAPI)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without scoutapm keyword, got %d", len(res))
	}
}

// TestFromData_BareKeywordNoArm guards the FP shape the hardening now rejects:
// high-entropy candidates sitting near a *bare* "scoutapm" word — prose, a
// script-src URL, a dependency name — with no assignment-style
// key/token/secret reference. The old radius-256 strings.Contains gate matched
// these; the arm-regex gate must not.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("see the scoutapm dashboard. unrelated values " + dummyAgent + " and " + dummyAPI + " appear here")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare-keyword-no-assignment shape, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected guards the degenerate-placeholder FP: a
// repeated-character run (e.g. the all-zeros scout_apm.yml template key) that
// clears the length regex and sits under a real assignment reference but has
// near-zero entropy. The entropy floor must cull it.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("scout_apm_agent_key=00000000000000000000\nscoutapm_api_key=" + dummyAPI)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for zero-entropy placeholder key, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != dummyAPI || p != dummyAgent {
			t.Errorf("basic auth mismatch: u=%q p=%q", u, p)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyAgent+":"+dummyAPI)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyAgent+":"+dummyAPI)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyAgent+":"+dummyAPI)
	if v {
		t.Fatal("expected verified=false on 5xx")
	}
}
