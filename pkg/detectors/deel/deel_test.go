package deel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyToken = "abcdefABCDEF0123456789abcdefABCDEF01234567890XYZ"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Deel {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("DEEL_API_TOKEN=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without deel keyword, got %d", len(res))
	}
}

// TestFromData_BareKeywordNoArm guards the radius/arm-regex tightening: a bare
// "deel" substring (e.g. the api.letsdeel.com host) without a token-assignment
// reference must no longer pull in a 40+ alnum run.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("see api.letsdeel.com for docs; ref=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare keyword without assignment arm, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected guards the entropy floor: a low-variety 40+
// char run sitting right next to a real "deel_api_token=" assignment clears the
// regex and arm gate but must be rejected as a false positive.
func TestFromData_LowEntropyRejected(t *testing.T) {
	lowEntropy := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 42 chars, entropy ~0
	body := []byte("deel_api_token=" + lowEntropy)
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
