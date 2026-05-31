package rekaai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.RekaAI {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("REKA_API_KEY=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED_VALUE=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_KeywordWithoutAssignment is the FP-hardening regression:
// a high-entropy 32-64 alnum run that merely shares a chunk with the bare
// word "reka" (prose, not an assignment) must no longer match now that the
// gate is an assignment-anchored arm regex within radius 64.
func TestFromData_KeywordWithoutAssignment(t *testing.T) {
	body := []byte("Reka builds frontier models. const build = " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (no assignment anchor near keyword), got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected confirms the conservative entropy floor
// drops a repetitive run that clears the broad regex but is not key material.
func TestFromData_LowEntropyRejected(t *testing.T) {
	lowEntropy := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 40 chars, entropy 0
	body := []byte("REKA_API_KEY=" + lowEntropy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low entropy), got %d", len(res))
	}
}

// TestFromData_ArmVariants keeps recall on the documented env-var/assignment
// shapes so the tighter gate does not silently cull real placements.
func TestFromData_ArmVariants(t *testing.T) {
	cases := []string{
		"REKA_API_KEY=" + dummy,
		"reka_token = \"" + dummy + "\"",
		"rekaai_secret: " + dummy,
		"reka.ai_api_key=" + dummy,
	}
	for _, c := range cases {
		res, _ := Scanner{}.FromData(context.Background(), false, []byte(c))
		if len(res) == 0 {
			t.Fatalf("expected >=1 for %q", c)
		}
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != dummy {
			t.Errorf("missing x-api-key")
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
