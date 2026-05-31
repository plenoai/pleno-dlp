package vercel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummy = "abcdefghijklmnopqrstuvwx" // 24 alphanumeric.

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("VERCEL_TOKEN="+dummy))
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

func TestFromData_NoKeyword_DoesNotMatch(t *testing.T) {
	// 24-alnum is too generic without a co-occurring "vercel" keyword.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("token="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_DashKeyword_Matches(t *testing.T) {
	// "vercel-token" (dash variant) within the window must arm the token.
	res, err := Scanner{}.FromData(context.Background(), false, []byte("vercel-token: "+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_DotVercelConfig_Matches(t *testing.T) {
	// A token in a .vercel/ config blob with a nearby VERCEL_TOKEN reference
	// (not immediately preceding) must still arm — proximity is two-sided.
	blob := "# .vercel/project.json\n" + dummy + "\nexport VERCEL_TOKEN=...\n"
	res, err := Scanner{}.FromData(context.Background(), false, []byte(blob))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_BareVercel_DoesNotMatch(t *testing.T) {
	// A bare "vercel" substring (e.g. a script-src URL or dependency name)
	// without a "vercel_token"-shaped reference must NOT arm — this is the
	// dominant SHA/nonce/k8s-name false-positive source.
	res, _ := Scanner{}.FromData(context.Background(), false,
		[]byte("https://vercel.com/deploy nonce="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_LowEntropy_DoesNotMatch(t *testing.T) {
	// A 24-char run that clears the alnum regex but has low entropy (a
	// padded identifier) must be rejected even when armed by the keyword.
	lowEntropy := "aaaaaaaaaaaabbbbbbbbbbbb" // 24 chars, entropy 1.0 bits/char.
	res, _ := Scanner{}.FromData(context.Background(), false,
		[]byte("VERCEL_TOKEN="+lowEntropy))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	// Wrong length — 23 chars — must not match.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("vercel: abcdefghijklmnopqrstuvw"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "abcdef") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummy {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
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

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}
