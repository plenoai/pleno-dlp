//go:build detector_unit

package zendesk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyTok = "abcdefghij0123456789ABCDEFGHIJabcdefghij"
const dummyEmail = "ops@example.com"

func TestFromData_Pair(t *testing.T) {
	body := "zendesk_email=" + dummyEmail + "\nzendesk_token=" + dummyTok
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyTok {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != dummyEmail {
		t.Fatalf("rawV2 mismatch: %q", res[0].RawV2)
	}
}

// TestFromData_DocumentedTokenScheme locks in recall for Zendesk's canonical
// documented credential `<email>/token:<api_token>`. The literal `/token:`
// scheme separator is the arm anchor here — there is no `zendesk_token=` style
// reference, so this exercises the second arm branch. Missing this shape
// would be a major recall gap.
func TestFromData_DocumentedTokenScheme(t *testing.T) {
	body := dummyEmail + "/token:" + dummyTok
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1 for documented <email>/token:<token> form, got %d", len(res))
	}
	if string(res[0].Raw) != dummyTok {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_HostCapture(t *testing.T) {
	body := "host=acme.zendesk.com\nzendesk_token=" + dummyTok
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if got := res[0].ExtraData["host"]; got != "acme.zendesk.com" {
		t.Fatalf("expected host capture, got %q", got)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("token="+dummyTok))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

// A bare `zendesk` substring (here a `<sub>.zendesk.com` host in a doc link)
// near a generic high-entropy 40-char base62 run is NOT an armed credential
// reference. The radius-64 arm regex `zendesk[_-]?(api[_-]?)?(token|key|secret)`
// must reject it — this is the FP shape the old radius-256 strings.Contains
// gate matched. dummyTok has entropy ~4.8, so this isolates the arm gate, not
// the entropy gate.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := "see https://acme.zendesk.com/docs build=" + dummyTok
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare-keyword non-armed match, got %d", len(res))
	}
}

// A low-entropy 40-char base62 run (repeated character) next to an armed
// `zendesk_token=` reference clears the length+charset regex and the arm gate
// but must be culled by HasMinEntropy(token, 3.5) — it is a placeholder, not a
// real token.
func TestFromData_ArmedLowEntropyRejected(t *testing.T) {
	lowEntropyTok := strings.Repeat("a", 40)
	body := "zendesk_token=" + lowEntropyTok
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy armed token, got %d", len(res))
	}
}

func setAPIBase(t *testing.T, url string) {
	t.Helper()
	orig := apiBase
	apiBase = url
	t.Cleanup(func() { apiBase = orig })
}

func TestVerify_Accepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/users/me.json" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if h := r.Header.Get("Authorization"); !strings.HasPrefix(h, "Basic ") {
			t.Errorf("missing Basic auth header, got %q", h)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"user":{"id":1}}`))
	}))
	defer srv.Close()
	setAPIBase(t, srv.URL)

	v, err := verifyCredential(context.Background(), "acme.zendesk.com", dummyEmail, dummyTok)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !v {
		t.Fatalf("expected verified=true on 200")
	}
}

func TestVerify_Rejected(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		setAPIBase(t, srv.URL)
		v, err := verifyCredential(context.Background(), "acme.zendesk.com", dummyEmail, dummyTok)
		srv.Close()
		if err != nil {
			t.Fatalf("code %d: expected no err, got %v", code, err)
		}
		if v {
			t.Fatalf("code %d: expected verified=false", code)
		}
	}
}

func TestVerify_Transient(t *testing.T) {
	for _, code := range []int{http.StatusInternalServerError, http.StatusTooManyRequests} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		setAPIBase(t, srv.URL)
		v, err := verifyCredential(context.Background(), "acme.zendesk.com", dummyEmail, dummyTok)
		srv.Close()
		if v {
			t.Fatalf("code %d: expected verified=false", code)
		}
		if err == nil {
			t.Fatalf("code %d: expected transient error, got nil", code)
		}
	}
}

func TestVerify_IncompleteNoProbe(t *testing.T) {
	// No apiBase override and no host: must not contact any server.
	v, err := verifyCredential(context.Background(), "", dummyEmail, dummyTok)
	if v || err != nil {
		t.Fatalf("expected (false,nil) for missing host, got (%v,%v)", v, err)
	}
	// Host present but email missing: still incomplete.
	v, err = verifyCredential(context.Background(), "acme.zendesk.com", "", dummyTok)
	if v || err != nil {
		t.Fatalf("expected (false,nil) for missing email, got (%v,%v)", v, err)
	}
}

func TestFromData_VerifySetsResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	setAPIBase(t, srv.URL)

	body := "host=acme.zendesk.com zendesk_email=" + dummyEmail + " zendesk_token=" + dummyTok
	res, err := Scanner{}.FromData(context.Background(), true, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if !res[0].Verified {
		t.Fatalf("expected Verified=true, err=%v", res[0].VerificationErr)
	}
}

func TestVerify_Triple(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	setAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), "acme.zendesk.com|"+dummyEmail+"|"+dummyTok)
	if err != nil || !v {
		t.Fatalf("expected verified triple, got (%v,%v)", v, err)
	}
	// Malformed triple no-ops.
	v, err = Scanner{}.Verify(context.Background(), "not-a-triple")
	if v || err != nil {
		t.Fatalf("expected (false,nil) for malformed secret, got (%v,%v)", v, err)
	}
}
