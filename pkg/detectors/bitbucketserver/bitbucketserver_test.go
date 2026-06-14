//go:build detector_unit

package bitbucketserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyHTTPAccess = "BBDC-OTQyNzgwNTk0NjI4OnUlfBFxe9SrJqZbnY7zxMbW1ZmgWQ5q"
const dummyPAT = "0123456789abcdefghijklmnopqrstuvwxyzABCD"

func TestFromData_HTTPAccess(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("STASH_TOKEN="+dummyHTTPAccess))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyHTTPAccess {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
	if res[0].Verified {
		t.Fatal("BitbucketServer is unverified-by-design (host unknown); got Verified=true")
	}
}

func TestFromData_PATWithKeyword(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("# bitbucket pat\nTOKEN="+dummyPAT))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyPAT {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_PATNoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("nonce="+dummyPAT))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

// FP regression: a bare "bitbucket" substring (prose/URL) within the old
// radius-256 window no longer arms a generic high-entropy 40-char run. The
// keyword is present but not in an assignment-anchor (`bitbucket_token`-style)
// shape, so the tightened arm-regex gate must reject it.
func TestFromData_PATBareKeywordRejected(t *testing.T) {
	// High-entropy 40-char base62 run (clears the entropy floor) sitting
	// near a bare "bitbucket" mention that is NOT a credential assignment.
	const fp = "See the bitbucket mirror at our repo host x9K2mQ7pL4vR8sN1tB6wY3cF5hD0jG2aZ7eU4iO"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(fp))
	if len(res) != 0 {
		t.Fatalf("bare-keyword high-entropy FP must be rejected, got %d", len(res))
	}
}

// FP regression: a low-entropy 40-char run inside a real assignment anchor is
// rejected by the entropy floor even though the arm regex matches.
func TestFromData_PATLowEntropyRejected(t *testing.T) {
	const lowEnt = "bitbucket_token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(lowEnt))
	if len(res) != 0 {
		t.Fatalf("low-entropy padded run must be rejected, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyHTTPAccess)
	if r == dummyHTTPAccess {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "BBDC-OTQ") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func withAPIBase(t *testing.T, url string) {
	t.Helper()
	old := apiBase
	apiBase = url
	t.Cleanup(func() { apiBase = old })
}

// No apiBase override => Verify must no-op (host unknown, no covert scan).
func TestVerify_NoAPIBaseNoOps(t *testing.T) {
	withAPIBase(t, "")
	v, err := Scanner{}.Verify(context.Background(), dummyHTTPAccess)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected no-op verified=false without apiBase")
	}
}

// 200 => authenticated admin token => verified=true, and the request must carry
// the bearer token against the documented endpoint.
func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+dummyHTTPAccess {
			t.Errorf("Authorization = %q, want bearer token", got)
		}
		if r.URL.Path != "/rest/api/1.0/users" {
			t.Errorf("path = %q, want /rest/api/1.0/users", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummyHTTPAccess)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true on 200")
	}
}

// 403 => valid token, insufficient (non-admin) scope => still verified=true.
func TestVerify_ForbiddenIsValid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummyHTTPAccess)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !v {
		t.Fatal("403 is a live non-admin token; expected verified=true")
	}
}

// 401 => no/invalid credentials => verified=false, no error.
func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummyHTTPAccess)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false on 401")
	}
}

// 500 and 429 => transient => verified=false WITH error (not an authoritative
// invalid verdict).
func TestVerify_TransientErrors(t *testing.T) {
	for _, code := range []int{http.StatusInternalServerError, http.StatusTooManyRequests} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		withAPIBase(t, srv.URL)
		v, err := Scanner{}.Verify(context.Background(), dummyHTTPAccess)
		srv.Close()
		if v {
			t.Fatalf("code %d: expected verified=false", code)
		}
		if err == nil {
			t.Fatalf("code %d: expected transient error", code)
		}
	}
}

// FromData wires Verify when verify==true.
func TestFromData_VerifyWired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	res, err := Scanner{}.FromData(context.Background(), true, []byte("STASH_TOKEN="+dummyHTTPAccess))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if !res[0].Verified {
		t.Fatal("expected Verified=true via FromData verify path")
	}
	if res[0].VerificationErr != nil {
		t.Fatalf("unexpected VerificationErr: %v", res[0].VerificationErr)
	}
}
