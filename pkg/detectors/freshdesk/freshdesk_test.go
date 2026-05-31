package freshdesk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const dummy = "fd0123456789abcdefABCD"

func TestFromData_Positive(t *testing.T) {
	body := "freshdesk_api_key=" + dummy
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_HostCapture(t *testing.T) {
	body := "host=acme.freshdesk.com\nfreshdesk_token=" + dummy
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if got := res[0].ExtraData["host"]; got != "acme.freshdesk.com" {
		t.Fatalf("expected host capture, got %q", got)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("random_token="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

// verifyServer returns an httptest.Server that asserts the Freshdesk Basic-auth
// convention (apikey as username, "X" as password) and responds with status.
func verifyServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/agents/me" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			t.Errorf("expected basic auth")
		}
		if user != dummy {
			t.Errorf("basic-auth user = %q, want apikey %q", user, dummy)
		}
		if pass != "X" {
			t.Errorf("basic-auth pass = %q, want %q", pass, "X")
		}
		w.WriteHeader(status)
	}))
}

func TestVerify_Accept200(t *testing.T) {
	srv := verifyServer(t, http.StatusOK)
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true on 200")
	}
}

func TestVerify_Reject401(t *testing.T) {
	srv := verifyServer(t, http.StatusUnauthorized)
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false on 401")
	}
}

func TestVerify_Reject403(t *testing.T) {
	srv := verifyServer(t, http.StatusForbidden)
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false on 403")
	}
}

func TestVerify_Transient500(t *testing.T) {
	srv := verifyServer(t, http.StatusInternalServerError)
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err == nil {
		t.Fatal("expected transient error on 500")
	}
	if v {
		t.Fatal("expected verified=false on 500")
	}
}

func TestVerify_Transient429(t *testing.T) {
	srv := verifyServer(t, http.StatusTooManyRequests)
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err == nil {
		t.Fatal("expected transient error on 429")
	}
	if v {
		t.Fatal("expected verified=false on 429")
	}
}

// Without an apiBase override and without a host packed alongside the key, the
// detector must not guess a tenant — it reports unverified with no error.
func TestVerify_NoHostNoOverride(t *testing.T) {
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if v {
		t.Fatal("expected verified=false without a derivable host")
	}
}

// FromData with verify=true derives the host from the chunk and verifies the
// key against it.
func TestFromData_VerifyUsesChunkHost(t *testing.T) {
	srv := verifyServer(t, http.StatusOK)
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	body := "host=acme.freshdesk.com\nfreshdesk_token=" + dummy
	res, _ := Scanner{}.FromData(context.Background(), true, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if !res[0].Verified {
		t.Fatalf("expected Verified=true, err=%v", res[0].VerificationErr)
	}
}

func TestRedact(t *testing.T) {
	if redact(dummy) == dummy {
		t.Fatalf("redact didn't redact: %q", redact(dummy))
	}
}
