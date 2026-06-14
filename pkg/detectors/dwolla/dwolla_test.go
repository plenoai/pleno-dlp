//go:build detector_unit

package dwolla

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Dwolla key/secret are each exactly 50 alphanumeric chars (upstream
// trufflehog pins `[a-zA-Z-0-9]{50}`). These dummies match that length.
const dummyKey = "ABCDEFabcdef0123456789ABCDEFabcdef0123456789ABCDEF"
const dummySecret = "ZYXWVUzyxwvu9876543210ZYXWVUzyxwvu9876543210ZYXWVU"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Dwolla {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("DWOLLA_KEY=" + dummyKey + "\nDWOLLA_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if string(res[0].RawV2) != dummySecret {
		t.Fatalf("expected RawV2=secret, got %q", res[0].RawV2)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token1=" + dummyKey + "\ntoken2=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without dwolla keyword, got %d", len(res))
	}
}

// Regression: a bare "dwolla" word (prose / URL / package name) near two
// high-entropy 50-char runs must NOT match. The hardened gate requires an
// assignment-style arm (dwolla_key / dwolla-secret / dwollaapitoken) within
// radius 64, not just the bare keyword over radius 256.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("see dwolla docs for setup\nfield1=" + dummyKey + "\nfield2=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare keyword without arm, got %d", len(res))
	}
}

// Regression: a low-entropy 50-char run next to a dwolla arm must be culled by
// the entropy floor even though it clears the alnum length regex.
func TestFromData_LowEntropyCulled(t *testing.T) {
	lowEntropy := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 50 'a'
	if len(lowEntropy) != 50 {
		t.Fatalf("fixture length %d != 50", len(lowEntropy))
	}
	body := []byte("dwolla_key=" + lowEntropy + "\ndwolla_secret=" + lowEntropy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy creds, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != dummyKey || p != dummySecret {
			t.Errorf("basic auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
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
		t.Fatal("expected verified=false on 5xx")
	}
}
