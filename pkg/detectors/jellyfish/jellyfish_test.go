//go:build detector_unit

package jellyfish

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "abcdef0123456789ABCDEFabcdef0123456789AB"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Jellyfish {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("JELLYFISH_API_KEY=" + dummy)
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

// genericHigh is a 40-char base62 run with high Shannon entropy (~5.1).
const genericHigh = "Xq7Lm2Zp9Rt4Wv6Yb3Nc8Df1Gh5Jk0Sl2Aq4Bz1V"

// TestFromData_BareKeywordNoAnchor is the FP-hardening regression: a generic
// high-entropy 40-char string that merely sits near a bare "jellyfish" prose
// mention (no assignment anchor). Under the old radius-256 bare strings.Contains
// gate this matched; the armRe assignment anchor must now reject it.
func TestFromData_BareKeywordNoAnchor(t *testing.T) {
	body := []byte("We use jellyfish for analytics. build hash " + genericHigh + " shipped.")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (bare keyword, no assignment anchor), got %d", len(res))
	}
}

// TestFromData_AnchoredHighEntropy confirms recall: the same high-entropy run
// IS reported when a real assignment-style Jellyfish reference is present.
func TestFromData_AnchoredHighEntropy(t *testing.T) {
	body := []byte("jellyfish_api_token = " + genericHigh)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1 (assignment-anchored high-entropy token)")
	}
}

// TestFromData_LowEntropyRejected confirms the conservative entropy floor
// rejects a structured low-information run even with the assignment anchor.
func TestFromData_LowEntropyRejected(t *testing.T) {
	lowEntropy := "aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbb" // ent ~1.0
	body := []byte("jellyfish_api_token = " + lowEntropy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (entropy floor), got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != dummy {
			t.Errorf("missing auth header")
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

func TestVerify_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
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
