//go:build detector_unit

package bitwarden

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "0.abcdef01-2345-6789-abcd-ef0123456789.AbCdEf0123456789AbCd:ZyXwVu9876543210ZyXw"

const (
	dummyClientID     = "abcdef01-2345-6789-abcd-ef0123456789"
	dummyClientSecret = "AbCdEf0123456789AbCd"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Bitwarden {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# bitwarden\nBWS_ACCESS_TOKEN=" + dummy)
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
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("# bitwarden\n" + dummy + "\nrepeat\n" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "0.abcdef01") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestParseToken(t *testing.T) {
	id, secret, ok := parseToken(dummy)
	if !ok {
		t.Fatal("expected parse ok")
	}
	if id != dummyClientID {
		t.Fatalf("client_id = %q, want %q", id, dummyClientID)
	}
	if secret != dummyClientSecret {
		t.Fatalf("client_secret = %q, want %q", secret, dummyClientSecret)
	}
	// encryption_key segment must not leak into client_secret.
	if strings.Contains(secret, "ZyXw") {
		t.Fatalf("encryption_key leaked into client_secret: %q", secret)
	}
}

func TestParseToken_Malformed(t *testing.T) {
	for _, bad := range []string{"", "0.onlyone", "noversion.uuid.secret:enc", "0.uuid.:enc", "0.uuid.secretnocolon"} {
		if _, _, ok := parseToken(bad); ok {
			t.Errorf("expected parse fail for %q", bad)
		}
	}
}

// verifyServer asserts the OAuth2 client_credentials form body and replies
// with the given status code.
func verifyServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connect/token" {
			t.Errorf("path = %q, want /connect/token", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		if got := r.PostForm.Get("grant_type"); got != "client_credentials" {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.PostForm.Get("scope"); got != "api.secrets" {
			t.Errorf("scope = %q", got)
		}
		if got := r.PostForm.Get("client_id"); got != dummyClientID {
			t.Errorf("client_id = %q, want %q", got, dummyClientID)
		}
		if got := r.PostForm.Get("client_secret"); got != dummyClientSecret {
			t.Errorf("client_secret = %q, want %q", got, dummyClientSecret)
		}
		w.WriteHeader(status)
		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	}))
}

func withAPIBase(t *testing.T, srv *httptest.Server) {
	t.Helper()
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
}

func TestVerify_OK(t *testing.T) {
	srv := verifyServer(t, http.StatusOK, `{"access_token":"eyJ...","expires_in":3600}`)
	defer srv.Close()
	withAPIBase(t, srv)

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true on 200")
	}
}

func TestVerify_Rejected(t *testing.T) {
	for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized} {
		srv := verifyServer(t, code, `{"error":"invalid_client"}`)
		withAPIBase(t, srv)
		v, err := Scanner{}.Verify(context.Background(), dummy)
		srv.Close()
		if err != nil {
			t.Fatalf("code %d: unexpected err %v", code, err)
		}
		if v {
			t.Fatalf("code %d: expected verified=false", code)
		}
	}
}

func TestVerify_TransientServerError(t *testing.T) {
	srv := verifyServer(t, http.StatusInternalServerError, "")
	defer srv.Close()
	withAPIBase(t, srv)

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false on 500")
	}
	if err == nil {
		t.Fatal("expected transient error on 500")
	}
}

func TestVerify_RateLimited(t *testing.T) {
	srv := verifyServer(t, http.StatusTooManyRequests, "")
	defer srv.Close()
	withAPIBase(t, srv)

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false on 429")
	}
	if err == nil {
		t.Fatal("expected transient error on 429 (surfaced as VerificationErr, not Verified)")
	}
}

func TestFromData_VerifySetsVerified(t *testing.T) {
	srv := verifyServer(t, http.StatusOK, `{"access_token":"eyJ..."}`)
	defer srv.Close()
	withAPIBase(t, srv)

	body := []byte("# bitwarden\nBWS_ACCESS_TOKEN=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), true, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if !res[0].Verified {
		t.Fatal("expected Verified=true")
	}
	if res[0].VerificationErr != nil {
		t.Fatalf("unexpected VerificationErr: %v", res[0].VerificationErr)
	}
}
