//go:build detector_unit

package razorpay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyKey    = "rzp_test_abcdef0123456789"
	dummySecret = "abcdef0123456789ABCDEFGH"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Razorpay {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# razorpay\nKEY=" + dummyKey + "\nSECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if string(res[0].Raw) != dummyKey {
		t.Fatalf("Raw mismatch: %s", res[0].Raw)
	}
	if string(res[0].RawV2) == "" {
		t.Fatal("RawV2 empty")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("KEY=" + dummyKey + "\nSECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_NoSecret(t *testing.T) {
	body := []byte("razorpay only key " + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without secret, got %d", len(res))
	}
}

// TestFromData_BareKeywordNoArm covers the FP shape the hardening now rejects:
// a valid-shaped key + a generic high-entropy 24-char secret sitting near a
// bare "razorpay" mention (e.g. a doc URL or package name) but with NO
// assignment-style reference (razorpay_key / razorpay-secret / "razorpay\nKEY=")
// anywhere in the tightened 64-byte window. Under the old radius-256 bare
// strings.Contains gate this matched; under the armRe gate it must not.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	// "razorpay" appears only as a prose/URL mention with no nearby
	// key/secret/token/id assignment word; the secret is high-entropy.
	body := []byte("see https://github.com/razorpay/razorpay-go for the SDK. " +
		"value " + dummyKey + " other " + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare-keyword-no-arm FP shape, got %d", len(res))
	}
}

// TestFromData_LowEntropySecretRejected covers a key id armed by a proper
// razorpay_secret reference but paired only with a low-entropy 24-char run
// (a padded/structured identifier, not a random secret). The {24} length
// regex matches it but the entropy floor must reject it, leaving no secret
// candidate and therefore no Result.
func TestFromData_LowEntropySecretRejected(t *testing.T) {
	// 24 chars, almost all 'a' -> Shannon entropy well below 3.5.
	lowEntropy := "aaaaaaaaaaaaaaaaaaaaaaab"
	if len(lowEntropy) != 24 {
		t.Fatalf("fixture not 24 chars: %d", len(lowEntropy))
	}
	body := []byte("razorpay_key=" + dummyKey + "\nrazorpay_secret=" + lowEntropy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy secret, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != dummyKey || p != dummySecret {
			t.Errorf("auth mismatch: %v / %v", u, p)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false")
	}
}
