//go:build detector_unit

package githubfinegrained

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var dummyPAT = "github_pat_" + strings.Repeat("A", 22) + "_" + strings.Repeat("b", 59)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.GitHubFineGrained {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Match(t *testing.T) {
	body := []byte("GITHUB_TOKEN=" + dummyPAT)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if string(res[0].Raw) != dummyPAT {
		t.Fatalf("raw mismatch")
	}
}

func TestFromData_NoPrefix(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+strings.Repeat("a", 90)))
	if len(res) != 0 {
		t.Fatalf("expected 0 without prefix, got %d", len(res))
	}
}

func TestFromData_TooShort(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("github_pat_"+strings.Repeat("A", 50)))
	if len(res) != 0 {
		t.Fatalf("expected 0 for short token, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte(dummyPAT + "\n" + dummyPAT)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummyPAT {
			t.Errorf("auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyPAT)
	if err != nil || !v {
		t.Fatalf("verified expected true: err=%v v=%v", err, v)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyPAT)
	if v {
		t.Fatal("expected verified=false")
	}
}
