package signifyd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyID = "abcdef0123456789ABCDEF"
const dummyKey = "1234567890abcdef1234567890ABCDEF"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Signifyd {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("SIGNIFYD_TEAM=" + dummyID + "\nSIGNIFYD_KEY=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED=" + dummyID + "\nOTHER=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_BareKeywordNoArm guards the FP shape the hardening rejects: two
// generic high-entropy alnum runs sitting near a bare "signifyd" mention (a doc
// link / host reference) but with no assignment-style key/token/secret anchor.
// The old radius-256 strings.Contains gate matched this; the armRe gate must
// not.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("// see https://api.signifyd.com for details\nVALUE_A=" + dummyID + "\nVALUE_B=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (bare keyword, no assignment anchor), got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected guards the entropy floor: a padded
// placeholder that clears the alnum regex and sits next to an armed
// SIGNIFYD_KEY reference must still be rejected as not a real credential.
func TestFromData_LowEntropyRejected(t *testing.T) {
	const lowEnt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	body := []byte("SIGNIFYD_KEY=" + lowEnt + "\nSIGNIFYD_KEY2=" + lowEnt)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low entropy), got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Errorf("missing auth header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummyKey)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummyKey)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummyKey)
	if v {
		t.Fatal("expected verified=false")
	}
}
