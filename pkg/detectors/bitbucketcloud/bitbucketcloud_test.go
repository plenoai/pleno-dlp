package bitbucketcloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Modern Atlassian API token: `ATCTT3xFfG` prefix, base64url body, terminating
// `=` + 8-char alphanumeric checksum. Shaped after the upstream trufflehog
// atlassian/v2 example (dummy bytes, not a real credential).
const dummyToken = "ATCTT3xFfG" + "N0GsZNgOGrQSHSnxiJVi00oHlRicyM0yMNuKCBfw6qOHVcCy4Hm89Gncl" + "=366BFE3A"

// Bitbucket Cloud app password / API token: authoritative `ATBB` prefix.
const dummyAppPassword = "ATBBabcdefghijklmnopqrstuvwxyz0123456789"

// FP regression: a bare high-entropy 32-char base62 string. Previously matched
// the unfounded `[A-Za-z0-9]{32}` legacy pattern; must no longer match even
// adjacent to the bitbucket keyword.
const fpHighEntropy = "aZ3kP9xQ7mW2rT5yB8nC1vD4fG6hJ0lK"

func TestFromData_AccessToken(t *testing.T) {
	body := []byte("BITBUCKET_TOKEN=" + dummyToken)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyToken {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_AppPassword(t *testing.T) {
	body := []byte("BITBUCKET_APP_PASSWORD=" + dummyAppPassword)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyAppPassword {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

// Regression: the bare 32-char base62 shape is no longer a recognised
// credential, even with the bitbucket keyword in the same line.
func TestFromData_BareHighEntropy_Rejected(t *testing.T) {
	withKW := []byte("BITBUCKET_APP_PASSWORD=" + fpHighEntropy)
	res, _ := Scanner{}.FromData(context.Background(), false, withKW)
	if len(res) != 0 {
		t.Fatalf("bare high-entropy string near keyword must not match, got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("bitbucket=short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyToken)
	if r == dummyToken {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "ATCTT3xF") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummyToken {
			t.Errorf("auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyToken)
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

	v, err := Scanner{}.Verify(context.Background(), dummyToken)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1" // unroutable
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyToken)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}
