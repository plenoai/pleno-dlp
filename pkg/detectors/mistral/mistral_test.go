//go:build detector_unit

package mistral

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const dummy = "abcdefghijABCDEFGHIJ0123456789AB"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("MISTRAL_API_KEY="+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("k="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// lowEntropyToken is a 32-char run that clears the [A-Za-z0-9]{32} regex but is
// a structured / low-variety string (entropy ~2.16, below the 3.0 floor). Even
// sitting right next to the keyword it must NOT be reported — this is the FP
// shape the entropy gate now rejects.
const lowEntropyToken = "deadbeefdeadbeefdeadbeefdeadbeef"

func TestFromData_LowEntropyRejected(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("MISTRAL_API_KEY="+lowEntropyToken))
	if len(res) != 0 {
		t.Fatalf("expected low-entropy token to be rejected, got %d", len(res))
	}
}

// TestFromData_KeywordTooFar exercises the tightened radius (256 -> 64): a real
// high-entropy token with the keyword present but beyond 64 chars must not match.
func TestFromData_KeywordTooFar(t *testing.T) {
	// 80-char filler pushes the keyword outside the 64-char window.
	filler := "// configuration block follows, see the section below for credential wiring //"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("mistral_api_key referenced here "+filler+" value "+dummy))
	if len(res) != 0 {
		t.Fatalf("expected token beyond keyword radius to be rejected, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	if redact(dummy) == dummy {
		t.Fatal("redact didn't redact")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummy {
			t.Errorf("auth mismatch")
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
