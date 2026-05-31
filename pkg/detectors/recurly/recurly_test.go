package recurly

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyToken = "abcdef0123456789ABCDEF0123456789"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Recurly {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("RECURLY_API_KEY=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("API_KEY=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without recurly keyword, got %d", len(res))
	}
}

// TestFromData_BareKeywordRejected is the FP regression: a generic high-entropy
// 32-char alphanumeric run sitting near a *bare* "recurly" mention (a doc link /
// prose reference, not an assignment-style key reference) used to match under
// the old radius-256 strings.Contains gate. The arm regex now requires a
// `recurly[_-]?(api[_-]?)?(token|key|secret)` shape, so this no longer fires.
func TestFromData_BareKeywordRejected(t *testing.T) {
	// dummyToken is high-entropy, so the entropy floor alone would not reject it;
	// this asserts the arm-regex gate, not the entropy gate.
	body := []byte("See the recurly migration guide. session=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare-keyword (non-assignment) context, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected is the FP regression for the entropy floor: a
// structured low-information 32-char run that clears the alnum regex and is
// armed by a recurly key reference, but is not a random token.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("RECURLY_API_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy run, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _, _ := r.BasicAuth()
		if u != dummyToken {
			t.Errorf("auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyToken)
	if err != nil || !v {
		t.Fatalf("expected verified=true: err=%v v=%v", err, v)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyToken)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyToken)
	if v {
		t.Fatal("expected verified=false on 5xx")
	}
}
