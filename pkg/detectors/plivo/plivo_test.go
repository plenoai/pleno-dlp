package plivo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyAuthID = "MAABCDEFGHIJKLMN1234"
	dummyToken  = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Plivo {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("PLIVO_AUTH_ID=" + dummyAuthID + "\nPLIVO_AUTH_TOKEN=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if string(res[0].Raw) != dummyAuthID {
		t.Fatalf("Raw should carry auth_id, got %q", res[0].Raw)
	}
}

func TestFromData_NoIDPrefix(t *testing.T) {
	// Without MA/SA prefix the regex shouldn't match.
	body := []byte("PLIVO_AUTH_ID=ABCDEFGHIJKLMNOPQR12\nPLIVO_AUTH_TOKEN=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without MA/SA prefix, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != dummyAuthID || p != dummyToken {
			t.Errorf("basic auth mismatch: u=%q p=%q", u, p)
		}
		if !strings.Contains(r.URL.Path, dummyAuthID) {
			t.Errorf("path missing auth_id")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyAuthID+":"+dummyToken)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyAuthID+":"+dummyToken)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyAuthID+":"+dummyToken)
	if v {
		t.Fatal("expected verified=false on 5xx")
	}
}
