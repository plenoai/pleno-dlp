package tailscale

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyAuth = "tskey-auth-kFcd1234567890-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEF"
const dummyAPI = "tskey-api-kFcd1234567890-ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkj"
const dummyOAuth = "tskey-client-kFcd1234567890-Ab_Cd9012345678_90AbCdEfGhIjKlMnOpQr"

func TestFromData_Auth(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("TS_AUTHKEY="+dummyAuth))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyAuth {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_API(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("TS_API_KEY="+dummyAPI))
	if len(res) != 1 {
		t.Fatalf("expected 1 api hit, got %d", len(res))
	}
}

// OAuth client secrets contain underscores in the body; the broadened regex
// must still match them so they reach Verify.
func TestFromData_OAuth(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("TS_OAUTH="+dummyOAuth))
	if len(res) != 1 {
		t.Fatalf("expected 1 oauth hit, got %d", len(res))
	}
	if string(res[0].Raw) != dummyOAuth {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("tskey-short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyAuth)
	if r == dummyAuth {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "tskey-auth-") {
		t.Fatalf("missing prefix: %q", r)
	}
}

// verifyServer wires an httptest server with the given status code and asserts
// the request shape (POST, form field key, urlencoded, no auth header).
func verifyServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/v2/secret-scanning/verify" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("content-type = %q", ct)
		}
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("Authorization header must be empty, got %q", auth)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.PostForm.Get("key") != dummyAuth {
			t.Errorf("form key = %q, want %q", r.PostForm.Get("key"), dummyAuth)
		}
		w.WriteHeader(status)
	}))
}

func withAPIBase(t *testing.T, url string) {
	t.Helper()
	old := apiBase
	apiBase = url
	t.Cleanup(func() { apiBase = old })
}

func TestVerify_Verified(t *testing.T) {
	srv := verifyServer(t, http.StatusNoContent)
	defer srv.Close()
	withAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummyAuth)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true on 204")
	}
}

func TestVerify_NotVerified(t *testing.T) {
	srv := verifyServer(t, http.StatusUnauthorized)
	defer srv.Close()
	withAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummyAuth)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false on 401")
	}
}

func TestVerify_TransientServerError(t *testing.T) {
	srv := verifyServer(t, http.StatusInternalServerError)
	defer srv.Close()
	withAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummyAuth)
	if v {
		t.Fatal("must not be verified on 500")
	}
	if err == nil {
		t.Fatal("expected transient error on 500")
	}
}

func TestVerify_RateLimited(t *testing.T) {
	srv := verifyServer(t, http.StatusTooManyRequests)
	defer srv.Close()
	withAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummyAuth)
	if v {
		t.Fatal("must not be verified on 429")
	}
	if err == nil {
		t.Fatal("expected transient error on 429")
	}
}

func TestFromData_VerifyWiresResult(t *testing.T) {
	srv := verifyServer(t, http.StatusNoContent)
	defer srv.Close()
	withAPIBase(t, srv.URL)

	res, err := Scanner{}.FromData(context.Background(), true, []byte("TS_AUTHKEY="+dummyAuth))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if !res[0].Verified {
		t.Fatal("expected Verified=true wired through FromData")
	}
	if res[0].VerificationErr != nil {
		t.Fatalf("unexpected VerificationErr: %v", res[0].VerificationErr)
	}
}
