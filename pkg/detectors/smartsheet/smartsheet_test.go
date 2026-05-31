package smartsheet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "ll352u9jujauoqz4gstvsae05"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Smartsheet {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# smartsheet\nSMARTSHEET_TOKEN=" + dummy)
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

// lowEntropyFP is a 28-char alnum run that matches the {24,64} regex and sits
// next to the keyword, but its Shannon entropy (~2.14 bits/char) is below the
// 3.0 floor. Before the FP-hardening it would have matched; it must not now.
const lowEntropyFP = "deadbeefdeadbeefdeadbeefdead"

func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("# smartsheet\nSMARTSHEET_TOKEN=" + lowEntropyFP)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected low-entropy FP to be rejected, got %d", len(res))
	}
}

// TestFromData_RadiusTightened confirms a token separated from the keyword by
// more than the new 64-char radius is no longer matched (it would have matched
// under the old radius-256 gate).
func TestFromData_RadiusTightened(t *testing.T) {
	filler := make([]byte, 80)
	for i := range filler {
		filler[i] = '.'
	}
	body := append([]byte("smartsheet"), filler...)
	body = append(body, []byte(" "+dummy)...)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected token beyond radius 64 to be rejected, got %d", len(res))
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
