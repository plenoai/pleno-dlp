//go:build detector_unit

package branchio

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyKey    = "key_live_abcdefghijklmnopqrstuvwxyz012345"
	dummySecret = "secret_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.BranchIO {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("branch_io key=" + dummyKey + " secret=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if !bytes.Equal(res[0].Raw, []byte(dummyKey)) {
		t.Fatalf("raw mismatch")
	}
	if !bytes.Equal(res[0].RawV2, []byte(dummySecret)) {
		t.Fatalf("rawv2 mismatch")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("k=" + dummyKey + " s=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without branch keyword, got %d", len(res))
	}
}

func TestFromData_NoSecret(t *testing.T) {
	body := []byte("branch_key=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without paired secret, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("branch_io=" + dummyKey + " " + dummySecret + "\nbranch_io=" + dummyKey + " " + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

// FP regression: bare "branch" / git-branch prose with a well-formed
// key_live_* token must not satisfy the keyword gate. (The detector
// is still permissive enough to fire on real Branch.io config; this
// test just guards against the previous `Keywords() = ["branch", ...]`
// + `contextKeywords = ["branch", ...]` behaviour.)
func TestFromData_FP_GitBranchProse(t *testing.T) {
	body := []byte("// branched off main; key=" + dummyKey + " secret=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("git-branch prose FP: expected 0, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("branch_secret") != dummySecret {
			t.Errorf("expected branch_secret query param")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyKey+"|"+dummySecret)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyKey+"|"+dummySecret)
	if v {
		t.Fatal("expected verified=false")
	}
}
