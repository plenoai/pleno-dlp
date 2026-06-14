//go:build detector_unit

package paylocity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyID = "abcdefABCDEF0123456789abcdef0123"
const dummySecret = "ZYXWVUTSRQPONMLKJIHGFEDCBA987654"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Paylocity {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("PAYLOCITY_CLIENT_ID=" + dummyID + "\nPAYLOCITY_CLIENT_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
	if string(res[0].RawV2) != dummySecret {
		t.Errorf("RawV2 mismatch: %s", res[0].RawV2)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("ID=" + dummyID + "\nSECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_BareKeywordNoAnchor is the FP-hardening regression: two generic
// high-entropy 32-char tokens sit near the bare word "paylocity" but with NO
// assignment-style reference (paylocity_client_id / _secret / _key / _token).
// The old radius-256 strings.Contains(window,"paylocity") gate matched these;
// the arm regex + radius-64 gate must now reject them.
func TestFromData_BareKeywordNoAnchor(t *testing.T) {
	body := []byte("// integrates with the paylocity platform\nFOO=" + dummyID + "\nBAR=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (no assignment anchor), got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected ensures a structured/padded 32-char run that
// clears the alnum regex AND sits next to a real anchor is still dropped by the
// entropy floor.
func TestFromData_LowEntropyRejected(t *testing.T) {
	const lowEnt = "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb" // 32 chars, entropy ~1.0
	body := []byte("PAYLOCITY_CLIENT_ID=" + lowEnt + "\nPAYLOCITY_CLIENT_SECRET=" + lowEnt)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (entropy floor), got %d", len(res))
	}
}

func TestVerify_Disabled_Default(t *testing.T) {
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false default")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		if u != dummyID || p != dummySecret {
			t.Errorf("basic-auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if err != nil || !v {
		t.Fatalf("err=%v v=%v", err, v)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false")
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
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false")
	}
}
