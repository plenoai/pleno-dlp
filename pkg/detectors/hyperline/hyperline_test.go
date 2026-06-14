//go:build detector_unit

package hyperline

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummyToken carries the documented `prod_`/`test_` prefix. The random tail
// keeps the original fixture body so the existing positive cases still detect.
const dummyToken = "prod_abcdefghijklmnopqrstuvwxyzABCDEF1234"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Hyperline {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("hyperline_api_key=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("apikey=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without hyperline keyword, got %d", len(res))
	}
}

// TestFromData_GenericHighEntropyNoPrefix is the FP-hardening regression: a
// high-entropy bare-alnum run sitting right next to the hyperline keyword used
// to match the old `[A-Za-z0-9]{32,80}` regex. With prefix anchoring it must no
// longer surface — only `prod_`/`test_`-prefixed keys are real Hyperline keys.
func TestFromData_GenericHighEntropyNoPrefix(t *testing.T) {
	body := []byte("hyperline_api_key=Zk9Qx2Lm7Rp4Tn8Wv3Yb6Cd1Hf5Js0Ag2Ue4")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for unprefixed high-entropy string, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("hyperline=" + dummyToken + "\nhyperline_key=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummyToken {
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
