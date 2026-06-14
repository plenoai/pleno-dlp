//go:build detector_unit

package keycdn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummyToken mirrors the documented KeyCDN secret-key shape: the `sk_prod_`
// prefix (https://www.keycdn.com/api) followed by a mixed-case alphanumeric
// suffix. Value is a fabricated literal, not a real credential.
const dummyToken = "sk_prod_zbSVNe8gVUMT4KjYcJWuyC86"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.KeyCDN {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("keycdn_api=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

// TestFromData_FoundNoKeywordContext confirms the prefix anchor matches even
// when the literal "keycdn" word is not adjacent to the token — the engine
// prefilter (Keywords) already guarantees the chunk mentions keycdn, and the
// `sk_prod_` prefix is the in-regex discriminator. This preserves recall for
// real keys that appear without a nearby "keycdn" substring.
func TestFromData_FoundNoKeywordContext(t *testing.T) {
	body := []byte("export API_KEY=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1 (prefix-anchored), got 0")
	}
}

// TestFromData_GenericHighEntropyRejected is the FP-hardening regression: a
// generic high-entropy alphanumeric run sitting right next to the keycdn
// keyword previously matched the bare `[A-Za-z0-9]{20,64}` regex. With the
// `sk_prod_` prefix anchor it must no longer match.
func TestFromData_GenericHighEntropyRejected(t *testing.T) {
	body := []byte("keycdn_api=Xk7Qz9Lm2Rt4Vw8Np1Bc5Df3Gh6Jk0")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for non-prefixed high-entropy string, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _, ok := r.BasicAuth()
		if !ok || u != dummyToken {
			t.Errorf("basic auth mismatch")
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
