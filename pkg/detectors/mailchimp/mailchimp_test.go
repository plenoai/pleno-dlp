//go:build detector_unit

package mailchimp

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummy = "0123456789abcdef0123456789abcdef-us17"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("MAILCHIMP_API_KEY="+dummy))
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

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("0123-us"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestExtractDC(t *testing.T) {
	dc, ok := extractDC(dummy)
	if !ok || dc != "us17" {
		t.Fatalf("expected us17, got %q ok=%v", dc, ok)
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasSuffix(r, "-us17") {
		t.Fatalf("DC suffix should be preserved: %q", r)
	}
	if !strings.HasPrefix(r, "01234567") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("anystring:"+dummy))
		if r.Header.Get("Authorization") != want {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBaseOverride
	apiBaseOverride = srv.URL
	defer func() { apiBaseOverride = old }()

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
	old := apiBaseOverride
	apiBaseOverride = srv.URL
	defer func() { apiBaseOverride = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}
