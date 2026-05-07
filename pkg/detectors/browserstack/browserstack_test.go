package browserstack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyUser = "demouserabc123"
	dummyKey  = "abcDEF1234567890ZxYW"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Browserstack {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("BROWSERSTACK_USERNAME=" + dummyUser + "\nBROWSERSTACK_ACCESS_KEY=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if string(res[0].Raw) != dummyUser || string(res[0].RawV2) != dummyKey {
		t.Fatalf("pair mismatch: raw=%q rawv2=%q", res[0].Raw, res[0].RawV2)
	}
}

func TestFromData_NoUser(t *testing.T) {
	body := []byte("BROWSERSTACK_ACCESS_KEY=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without user, got %d", len(res))
	}
}

func TestFromData_NoKey(t *testing.T) {
	body := []byte("BROWSERSTACK_USERNAME=" + dummyUser)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without key, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != dummyUser || p != dummyKey {
			t.Errorf("auth mismatch: %q %q ok=%v", u, p, ok)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyUser+":"+dummyKey)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyUser+":"+dummyKey)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyUser+":"+dummyKey)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_BadFormat(t *testing.T) {
	v, err := Scanner{}.Verify(context.Background(), "no-colon-here")
	if err != nil || v {
		t.Fatalf("expected (false, nil), got (%v, %v)", v, err)
	}
}
