//go:build detector_unit

package coinbase

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyKey = "abcdef0123456789ABCDEF0123456789"
const dummySecret = "zyxwvu9876543210ZYXWVU9876543210abcdefghABCDEFGH0123456789012345"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Coinbase {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("COINBASE_API_KEY=" + dummyKey + " COINBASE_API_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED_KEY=" + dummyKey + " UNRELATED_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_BareKeywordNoArm guards the FP shape the hardening rejects:
// high-entropy 32/64-char alnum runs sitting near a bare "coinbase" mention
// (a doc link, blog text) but with no `coinbase_(api_)?(key|secret|token)`
// assignment anchor. Pre-hardening the radius-256 strings.Contains gate
// matched this; post-hardening the radius-64 arm regex must not.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("see https://www.coinbase.com/price for details " +
		dummyKey + " " + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (bare keyword, no assignment anchor), got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected guards the entropy floor: a 32-char run
// that clears the alnum regex and sits next to a proper assignment anchor
// but is a structured placeholder, not a random token.
func TestFromData_LowEntropyRejected(t *testing.T) {
	lowEntropyKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 32 'a', entropy 0
	body := []byte("COINBASE_API_KEY=" + lowEntropyKey + " COINBASE_API_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low-entropy key), got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("CB-ACCESS-KEY") != dummyKey {
			t.Errorf("missing key header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyKey)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyKey)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyKey)
	if v {
		t.Fatal("expected verified=false")
	}
}
