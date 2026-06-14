//go:build detector_unit

package nearrpc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "abcdef0123456789ABCDEF0123456789abcdef01"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.NearRPC {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("PAGODA_API_KEY=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED_VALUE=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// FP regression: a high-entropy 40-char alnum run sitting near a *bare*
// "pagoda" mention (prose / docs link / dependency name) must no longer arm.
// The old radius-256 strings.Contains gate matched this; the assignment-anchor
// armRe (pagoda_api_key etc.) within radius 64 does not.
func TestFromData_BareKeywordNoLongerArms(t *testing.T) {
	body := []byte("See the pagoda docs for details. nonce " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (bare keyword should not arm), got %d", len(res))
	}
}

// FP regression: a low-entropy 40-char run armed by a real assignment anchor
// must be culled by the entropy floor.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("PAGODA_API_KEY=" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low entropy should be culled), got %d", len(res))
	}
}

// Recall guard: alternate assignment shapes that real configs use must still
// arm (kept alongside the existing PAGODA_API_KEY positive in TestFromData_Found).
func TestFromData_AltAnchorsArm(t *testing.T) {
	for _, prefix := range []string{"NEAR_RPC_API_KEY=", "fastnear-token: ", "nearrpc_secret="} {
		body := []byte(prefix + dummy)
		res, _ := Scanner{}.FromData(context.Background(), false, body)
		if len(res) == 0 {
			t.Fatalf("expected >=1 for anchor %q", prefix)
		}
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != dummy {
			t.Errorf("missing x-api-key")
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

func TestVerify_NoApiBase(t *testing.T) {
	old := apiBase
	apiBase = ""
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil || v {
		t.Fatalf("expected unverified no-error, got v=%v err=%v", v, err)
	}
}
