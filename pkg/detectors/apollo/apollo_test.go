//go:build detector_unit

package apollo

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "abcdef0123456789ABCDEF"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Apollo {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("APOLLO_API_KEY=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_RequiresTightProviderPrefix(t *testing.T) {
	tests := map[string]string{
		"keyword after token":         dummy + " apollo",
		"keyword too far from token":  "apollo=" + strings.Repeat("x", 41) + dummy,
		"non-provider token alphabet": "apollo=abcdef0123456789ABCD_-",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			res, err := Scanner{}.FromData(context.Background(), false, []byte(input))
			if err != nil {
				t.Fatalf("FromData: %v", err)
			}
			if len(res) != 0 {
				t.Fatalf("expected 0 candidates, got %d", len(res))
			}
		})
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/health" {
			t.Errorf("path = %q, want /api/v1/auth/health", r.URL.Path)
		}
		if r.Header.Get("X-Api-Key") != dummy {
			t.Errorf("api key mismatch")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type = %q, want application/json", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("Cache-Control") != "no-cache" {
			t.Errorf("cache control = %q, want no-cache", r.Header.Get("Cache-Control"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"healthy":true,"is_logged_in":true}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil || !v {
		t.Fatalf("err=%v v=%v", err, v)
	}
}

func TestVerify_OKBodyDoesNotConfirmLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"healthy":true,"is_logged_in":false}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v {
		t.Fatal("HTTP 200 without an authenticated session must not verify")
	}
}

func TestVerify_AuthenticatedButUnhealthyIsIndeterminate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"healthy":false,"is_logged_in":true}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v || err == nil {
		t.Fatalf("unhealthy authenticated response = (verified=%v, err=%v), want indeterminate", v, err)
	}
}

func TestVerify_MalformedOKBodyIsIndeterminate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v || err == nil {
		t.Fatalf("malformed provider response = (verified=%v, err=%v), want indeterminate", v, err)
	}
}

func TestVerify_MissingRequiredFieldIsIndeterminate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"healthy":true}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v || err == nil {
		t.Fatalf("missing field = (verified=%v, err=%v), want indeterminate", v, err)
	}
}

func TestVerify_TrailingJSONIsIndeterminate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(
			`{"healthy":true,"is_logged_in":true}{"healthy":true,"is_logged_in":true}`,
		))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v || err == nil {
		t.Fatalf("trailing JSON = (verified=%v, err=%v), want indeterminate", v, err)
	}
}

func TestVerify_OversizedBodyIsIndeterminate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxVerificationResponseBytes+1))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v || err == nil {
		t.Fatalf("oversized body = (verified=%v, err=%v), want indeterminate", v, err)
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

func TestVerify_ForbiddenIsIndeterminate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v || err == nil {
		t.Fatalf("forbidden = (verified=%v, err=%v), want indeterminate", v, err)
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
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v || err == nil {
		t.Fatalf("server error = (verified=%v, err=%v), want indeterminate", v, err)
	}
}

func TestVerify_RedirectIsIndeterminateAndDoesNotForwardKey(t *testing.T) {
	var redirected bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected = true
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer source.Close()

	old := apiBase
	apiBase = source.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v || err == nil {
		t.Fatalf("redirect = (verified=%v, err=%v), want indeterminate", v, err)
	}
	if redirected {
		t.Fatal("verification credential followed a redirect")
	}
}
