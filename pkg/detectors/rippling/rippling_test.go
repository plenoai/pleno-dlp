//go:build detector_unit

package rippling

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyToken = "abcdefABCDEF0123456789abcdefABCDEF01234567890XYZ"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Rippling {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	// Assignment-anchored Rippling token reference: the hardened arm regex
	// requires a `rippling[_-]?(api[_-]?)?(token|key|secret)` shape near the
	// candidate, which this realistic env-var key satisfies.
	body := []byte("RIPPLING_API_TOKEN=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

// TestFromData_BareEnvVarForms locks in recall for the suffix-less env-var
// shapes (RIPPLING_API / RIPPLING_AUTH / RIPPLING_CREDENTIAL). These were the
// pre-hardening positive shapes; the arm regex must keep matching them so
// credentials assigned to those keys are not silently dropped.
func TestFromData_BareEnvVarForms(t *testing.T) {
	for _, key := range []string{"RIPPLING_API", "RIPPLING_AUTH", "RIPPLING_CREDENTIAL"} {
		body := []byte(key + "=" + dummyToken)
		res, _ := Scanner{}.FromData(context.Background(), false, body)
		if len(res) == 0 {
			t.Fatalf("%s=: expected >=1, got 0 (arm-regex recall regression)", key)
		}
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without rippling keyword, got %d", len(res))
	}
}

// TestFromData_BareKeywordRejected guards the radius/arm tightening: a bare
// "rippling" substring (a doc link, package name) near a high-entropy token is
// no longer enough — without an assignment-style token/key/secret reference
// the candidate must be rejected.
func TestFromData_BareKeywordRejected(t *testing.T) {
	body := []byte("// see https://developer.rippling.com docs\nsha=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare rippling keyword (no assignment anchor), got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected guards the entropy floor: a 40+ char run that
// is armed by a real-looking key reference but has no randomness (a padded or
// repeated identifier) must not surface.
func TestFromData_LowEntropyRejected(t *testing.T) {
	lowEntropy := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 44x 'A'
	body := []byte("RIPPLING_API_KEY=" + lowEntropy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy run, got %d", len(res))
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
