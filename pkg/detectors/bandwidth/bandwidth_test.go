package bandwidth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyUser = "abcdef1234567890"
const dummyPass = "ZYXWVU9876543210zyxwvu"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Bandwidth {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("BANDWIDTH_USER=" + dummyUser + "\nBANDWIDTH_PASS=" + dummyPass)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("USER=" + dummyUser + "\nPASS=" + dummyPass)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without bandwidth keyword, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected guards the FP-hardening entropy floor.
// `aaaaaaaaaaaaaaaa` / `bbbbbbbbbbbbbbbbbbbb` clear the bare
// `[A-Za-z0-9]{10,32}` regex and sit on `BANDWIDTH_*` assignment lines,
// so the old detector emitted them as a username/password pair. With the
// HasMinEntropy(token, 3.0) gate they must no longer match.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("BANDWIDTH_USER=aaaaaaaaaaaaaaaa\nBANDWIDTH_PASS=bbbbbbbbbbbbbbbbbbbb")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy run near keyword, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		if u != dummyUser || p != dummyPass {
			t.Errorf("auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyUser+":"+dummyPass)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyUser+":"+dummyPass)
	if v {
		t.Fatal("expected verified=false")
	}
}
