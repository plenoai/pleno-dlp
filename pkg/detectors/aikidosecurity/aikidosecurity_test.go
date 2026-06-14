//go:build detector_unit

package aikidosecurity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "AbCdEf0123456789AbCdEf0123456789AbCdEf01"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.AikidoSecurity {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# aikido\nAIKIDO_TOKEN=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

// TestFromData_BareKeywordRejected is the FP shape the radius-256 bare-Contains
// gate used to accept: a generic high-entropy base62 run sitting near a bare
// "aikido" mention (prose / dependency name) with NO `aikido_<token|key|secret>`
// assignment. The armed regex gate must now reject it.
func TestFromData_BareKeywordRejected(t *testing.T) {
	body := []byte("// installed via aikido cli\nSESSION_NONCE=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare-keyword FP shape, got %d", len(res))
	}
}

// TestFromData_AssignmentVariants keeps recall on the credential assignment
// shapes the armed regex is meant to cover (token/key/secret, with the optional
// api infix and separator variants).
func TestFromData_AssignmentVariants(t *testing.T) {
	for _, kw := range []string{"AIKIDO_TOKEN", "aikido-api-key", "aikido_secret", "AIKIDO_API_TOKEN"} {
		body := []byte(kw + "=" + dummy)
		res, _ := Scanner{}.FromData(context.Background(), false, body)
		if len(res) == 0 {
			t.Fatalf("expected >=1 for %q assignment, got 0", kw)
		}
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummy {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil || !v {
		t.Fatalf("verified expected true: err=%v v=%v", err, v)
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

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false")
	}
}
