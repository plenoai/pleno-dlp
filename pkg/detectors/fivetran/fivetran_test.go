//go:build detector_unit

package fivetran

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyKey = "abcdef0123456789ABCD"
const dummySecret = "ZYXWVU9876543210zyxw"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Fivetran {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("FIVETRAN_API_KEY=" + dummyKey + " FIVETRAN_API_SECRET=" + dummySecret)
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

// TestFromData_TwoUnrelatedIDs: a bare "fivetran" mention co-occurring with two
// unrelated 20-char alnum IDs (a git SHA-like build hash and an asset id) must
// NOT pair them — there is no assignment anchor near either half.
func TestFromData_TwoUnrelatedIDs(t *testing.T) {
	body := []byte("# fivetran connector notes\n" +
		"build commit a1b2c3d4e5f60718293A and asset Qz9Xy8Wv7Ut6Sr5Qp4Oz referenced in the changelog above.")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (no assignment anchor near either ID), got %d", len(res))
	}
}

// TestFromData_AnchoredPair: an assignment anchor (FIVETRAN_KEY:) within radius
// 64 of one half arms the pair even when only one side carries the anchor word.
func TestFromData_AnchoredPair(t *testing.T) {
	body := []byte("fivetran_key: " + dummyKey + "\nsecret: " + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1 anchored pair")
	}
	want := dummyKey + ":" + dummySecret
	if string(res[0].RawV2) != want {
		t.Fatalf("RawV2=%q want %q", string(res[0].RawV2), want)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != dummyKey || p != dummySecret {
			t.Errorf("missing basic auth")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false")
	}
}
