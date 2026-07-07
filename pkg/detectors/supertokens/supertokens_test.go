//go:build detector_unit

package supertokens

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "abcdef0123456789ABCDEFabcdef0123456789AB"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Supertokens {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("SUPERTOKENS_API_KEY=" + dummy)
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

// TestFromData_BareKeywordNoArm guards the FP-hardening: a generic
// high-entropy alnum string sitting near a *bare* "supertokens" mention must
// no longer match now that the gate requires an armRe-style
// supertokens_(api_)?key|token|secret reference within radius 64.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("we migrated auth to supertokens last quarter; build sha " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (bare keyword, no assignment arm), got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected guards the entropy floor: a 20+ char run
// that clears the charset regex but is low-information must be rejected
// even when properly armed.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("SUPERTOKENS_API_KEY=aaaaaaaaaaaaaaaaaaaaAAAA")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low entropy), got %d", len(res))
	}
}

// TestFromData_DocumentedCharset confirms recall for the documented charset:
// keys may contain '=' and '-' and be as short as 20 chars. This is the
// SuperTokens-documented example key shape and must detect.
func TestFromData_DocumentedCharset(t *testing.T) {
	// Documented example shape: alnum + '=' + '-', operator-chosen.
	key := "Akjnv3iunvsoi8=-sackjij3ncisds"
	body := []byte("super-tokens-key: " + key)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1 for documented charset key")
	}
}

func TestVerify_NoBase(t *testing.T) {
	old := apiBase
	apiBase = ""
	defer func() { apiBase = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false without apiBase")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("api-key") != dummy {
			t.Errorf("missing header")
		}
		w.WriteHeader(http.StatusOK)
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
