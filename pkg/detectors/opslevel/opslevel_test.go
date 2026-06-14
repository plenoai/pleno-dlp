//go:build detector_unit

package opslevel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "abcdef0123456789ABCDEF0123456789abcdef01"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.OpsLevel {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("OPSLEVEL_API_TOKEN=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED_TOKEN=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// A bare "opslevel" mention (doc URL, dependency name) near a high-entropy
// alnum run must NOT arm: the assignment-anchor arm regex requires a
// token/key/secret reference, not just the vendor word.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("see https://docs.opslevel.com guide, build sha " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (bare keyword, no arm), got %d", len(res))
	}
}

// A 36-64 char alnum run that is armed but low-entropy (padded identifier,
// repeated pattern) must be rejected by the entropy floor.
func TestFromData_LowEntropyRejected(t *testing.T) {
	lowEnt := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 40 chars, entropy 0
	body := []byte("OPSLEVEL_API_TOKEN=" + lowEnt)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low entropy), got %d", len(res))
	}
}

// The only authoritative OpsLevel sample (docs.opslevel.com/docs/package-versions)
// is a 36-char mixed-case alnum token; recall must cover it.
func TestFromData_DocumentedShape(t *testing.T) {
	docSample := "ABfFuAsAHou3XzyVW8nmeNqK86FAZCG3OHmK" // 36 chars, from official docs
	body := []byte("OPSLEVEL_API_TOKEN=" + docSample)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1 for documented 36-char shape")
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
