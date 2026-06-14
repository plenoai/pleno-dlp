//go:build detector_unit

package awx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummy is a 30-char base62 string in the shape of an oauthlib-generated AWX
// token (length 30, charset [A-Za-z0-9]), with high entropy. Not a real token.
const dummy = "rQONsve372fQwuc2pn76k3IHDCYpi7"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.AWX {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# awx_token\nAWX_OAUTH=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected pins the new entropy floor: a 30-char run
// that satisfies the bare [A-Za-z0-9]{30} regex AND sits right beside the
// keyword assignment, but is low-information (repeated fragment), must no
// longer be reported. This is the FP shape the hardening closes.
func TestFromData_LowEntropyRejected(t *testing.T) {
	const lowEntropy = "abc123abc123abc123abc123abc123" // 30 chars, H ~= 2.58 < 3.5
	body := []byte("awx_token=" + lowEntropy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected low-entropy token rejected, got %d", len(res))
	}
}

// TestFromData_KeywordTooFar pins the radius tightening 256 -> 64: a high-
// entropy real-shaped token whose nearest keyword is >64 chars away must not
// match, whereas the same token within 64 chars still matches.
func TestFromData_KeywordTooFar(t *testing.T) {
	filler := make([]byte, 80)
	for i := range filler {
		filler[i] = ' '
	}
	body := []byte("awx_token=" + string(filler) + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected no match when keyword is >64 chars away, got %d", len(res))
	}
}

// TestFromData_RealLengthDocExample guards recall against the documented
// AWX/oauthlib 30-char token length, using the second example token from the
// AWX token-auth docs. The prior 40-char pin would have missed this entirely.
func TestFromData_RealLengthDocExample(t *testing.T) {
	const docToken = "9epHOqHhnXUcgYK8QanOmUQPSgX92g" // 30 chars, from AWX docs
	body := []byte("AWX_OAUTH_TOKEN=" + docToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected documented 30-char token to match, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("awx_token=" + dummy + "\nawx_token=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/me/" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+dummy {
			t.Errorf("missing bearer")
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
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false")
	}
	if err == nil {
		t.Fatal("expected transient error on 500, got nil")
	}
}

func TestVerify_RateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false")
	}
	if err == nil {
		t.Fatal("expected transient error on 429, got nil")
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
