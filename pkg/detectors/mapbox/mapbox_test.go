package mapbox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummy token with payload `{"u":"testuser"}` base64url-encoded.
const dummy = "sk.eyJhbGciOiJIUzI1NiJ9.eyJ1IjoidGVzdHVzZXIifQ.AbCdEf0123456789AbCdEf0123456789"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Mapbox {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("MAPBOX_SECRET=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Severity != detectors.SeverityCritical {
		t.Fatalf("expected SeverityCritical, got %v", res[0].Severity)
	}
	if res[0].ExtraData["username"] != "testuser" {
		t.Fatalf("username mismatch: %q", res[0].ExtraData["username"])
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	// pk. (public) tokens must not be reported.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("MAPBOX_PUB=pk.eyJhbGciOiJIUzI1NiJ9.eyJ1IjoidGVzdHVzZXIifQ.AbCdEf0123456789AbCdEf0123456789"))
	if len(res) != 0 {
		t.Fatalf("expected 0 for pk., got %d", len(res))
	}
}

func TestFromData_InvalidPayload(t *testing.T) {
	// sk.<garbage>.<garbage>.<garbage> — payload doesn't JSON-decode to {u:..}.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X=sk.aaaaaaaaaaaaaa.bbbbbbbbbbbbbb.cccccccccccccc"))
	if len(res) != 0 {
		t.Fatalf("expected 0 for non-JSON payload, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/tokens/v2/testuser") {
			t.Errorf("path mismatch: %q", r.URL.Path)
		}
		if r.URL.Query().Get("access_token") != dummy {
			t.Errorf("token mismatch: %q", r.URL.Query().Get("access_token"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
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

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}
