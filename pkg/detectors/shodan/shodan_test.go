package shodan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummy = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("SHODAN_API_KEY="+dummy))
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

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

// Regression: a high-entropy 32-char alnum string near a *bare* "shodan"
// substring (a CLI mention, doc URL, dependency name) must no longer match.
// Before hardening the radius-256 bare-keyword Contains armed on any "shodan";
// now an assignment-shaped `shodan...key` reference within radius 64 is
// required, so this generic shape is rejected.
func TestFromData_BareKeywordRejected(t *testing.T) {
	// dummy has entropy 5.0 — it clears the entropy floor, so only the arm
	// regex change is responsible for rejecting this case.
	in := "see https://github.com/achillean/shodan-python for docs; ref " + dummy
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(in))
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare-keyword high-entropy FP shape, got %d", len(res))
	}
}

// Regression: a low-information 32-char run armed by a real `SHODAN_API_KEY`
// reference must be rejected by the entropy floor (it clears the alnum regex
// and the arm regex but is not a random key).
func TestFromData_LowEntropyRejected(t *testing.T) {
	const padded = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 32 chars, entropy 0
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("SHODAN_API_KEY="+padded))
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy run, got %d", len(res))
	}
}

// The arm regex must accept the common assignment shapes, not just the exact
// SHODAN_API_KEY casing.
func TestFromData_ArmVariants(t *testing.T) {
	for _, in := range []string{
		"shodan_api_key = " + dummy,
		"shodan-token: " + dummy,
		"shodanApiKey=" + dummy,
		"my_shodan_secret " + dummy,
	} {
		res, err := Scanner{}.FromData(context.Background(), false, []byte(in))
		if err != nil {
			t.Fatalf("err for %q: %v", in, err)
		}
		if len(res) != 1 {
			t.Fatalf("expected 1 for %q, got %d", in, len(res))
		}
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "AbCdEf") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != dummy {
			t.Errorf("key query mismatch: %q", r.URL.Query().Get("key"))
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
