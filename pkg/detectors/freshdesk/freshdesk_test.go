//go:build detector_unit

package freshdesk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
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

// Bare keyword co-occurrence (no assignment anchor, no host) must NOT arm a
// generic alnum token. The old 256-byte bare-keyword gate would have fired.
func TestFromData_BareKeywordNoAnchor(t *testing.T) {
	body := "see the freshdesk connector docs\nsome_value " + dummy
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected 0 on bare keyword without anchor/host, got %d", len(res))
	}
}

// Regression: a 40-char git SHA-1 sitting near the word "freshdesk" must NOT
// be reported. This is the headline false positive: the old tokenRe upper
// bound of 40 matched the SHA, and its entropy (~3.74) clears the 3.5 floor,
// so only the dropped 40-bound stops it.
func TestFromData_GitSHANearKeyword_Negative(t *testing.T) {
	const sha = "da39a3ee5e6b4b0d3255bfef95601890afd80709" // 40-char SHA-1
	body := "freshdesk connector bump to " + sha + " (see PR #42)"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected 0 for git SHA near freshdesk, got %d (raw=%q)", len(res), rawList(res))
	}
}

// Even with an explicit assignment anchor, a 40-char SHA assigned to a
// freshdesk-looking variable must be excluded by the length cap.
func TestFromData_GitSHAWithAnchor_Negative(t *testing.T) {
	const sha = "356a192b7913b04c54574d18c28d46e6395428ab" // 40-char SHA-1
	body := "freshdesk_revision=" + sha
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected 0 for 40-char SHA assigned to freshdesk var, got %d (raw=%q)", len(res), rawList(res))
	}
}

// Positive: an assignment-style anchor with no freshdesk.com host present must
// still arm the token (host OR anchor, not host AND anchor).
func TestFromData_AnchorNoHost_Positive(t *testing.T) {
	body := `FRESHDESK_API_KEY = "` + dummy + `"`
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1 from anchor without host, got %d", len(res))
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

// Low-entropy degenerate run that clears the length floor must be dropped by
// the secondary entropy filter even with a valid anchor.
func TestFromData_LowEntropy_Negative(t *testing.T) {
	body := "freshdesk_api_key=aaaaaaaaaaaaaaaaaaaa" // 20 'a's
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy run, got %d", len(res))
	}
}

func rawList(res []detectors.Result) []string {
	out := make([]string, len(res))
	for i, r := range res {
		out[i] = string(r.Raw)
	}
	return out
}

// verifyServer returns an httptest.Server that asserts the Freshdesk
// Basic-auth convention and responds with status.
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
