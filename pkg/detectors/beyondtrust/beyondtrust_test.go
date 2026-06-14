//go:build detector_unit

package beyondtrust

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummy is a 128-char alnum string (the documented BeyondTrust API-key
// length) shaped to look like a real high-entropy key. Not a real secret.
const dummy = "BpLnfgDsc2WD8F2qNfHK5a84jjJkwzDkh9h2fhfUVuS9jZ8uVbhV3vC5AWX39IVUWSP2NcHciWvqZTa2N95RxRTZHWUsaD6HEdz0ThbXfQ6pYSQ3n267l1VQKGNbSuJE"

// fpToken is a 128-char string whose 64-char window contains the bare
// "beyondtrust" keyword WITHOUT an assignment arm (no key/token/secret). The
// hardened arm regex must reject this generic high-entropy run.
const fpToken = "KSiOW4eQ7sklpgstrQZtAcrsGvPnYSXMOpFIpPzS7iI4N1gN6lD0rYjTJXJXORIpfMGxOaIIFFFtsYlnymgdluV7UoqjQ2RAM3SZ2sOC7fysesy5tXyVyY9gZA4iSIR2"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.BeyondTrust {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("BEYONDTRUST_API_KEY=" + dummy)
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

// TestFromData_BareKeywordNoArm is the FP regression: a high-entropy 128-char
// token sitting near the bare "beyondtrust" keyword but with no assignment arm
// (key/token/secret). Pre-hardening the radius-256 Contains gate matched this;
// the arm regex must now reject it.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("see the beyondtrust dashboard for details: " + fpToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (bare keyword, no arm), got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "PS-Auth key="+dummy) {
			t.Errorf("missing PS-Auth, got %q", auth)
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

func TestVerify_NoApiBase(t *testing.T) {
	old := apiBase
	apiBase = ""
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil || v {
		t.Fatalf("expected unverified no-error, got v=%v err=%v", v, err)
	}
}
