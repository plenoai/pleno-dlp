package buddyci

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummyToken matches Buddy's documented UUID-v4 PAT shape (see the package
// doc comment / buddy.works Hello World example) without being a real token.
const dummyToken = "732e9e20-50ba-4047-8a7b-c9b17259a2a2"

// fpToken is a generic high-entropy alphanumeric run that the OLD bare
// [A-Za-z0-9]{40,80} regex matched. With the UUID anchor it no longer even
// matches the token regex, so it must never surface even right next to the
// keyword. Regression guard against the false-positive shape we just closed.
const fpToken = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.BuddyCI {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("buddy_token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without buddy keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("buddy_token=" + dummyToken + "\nbuddy_api_key=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

// TestFromData_RejectsGenericHighEntropy is the FP regression guard: the
// generic 50-char alnum run that the old bare regex flagged must no longer
// surface even when sitting directly next to a buddy_token= reference.
func TestFromData_RejectsGenericHighEntropy(t *testing.T) {
	body := []byte("buddy_token=" + fpToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected generic high-entropy run to be rejected, got %d", len(res))
	}
}

// TestFromData_RejectsDegenerateUUID confirms the entropy floor culls a
// structurally valid but zero-information UUID near the keyword.
func TestFromData_RejectsDegenerateUUID(t *testing.T) {
	body := []byte("buddy_token=00000000-0000-0000-0000-000000000000")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected degenerate UUID to be rejected, got %d", len(res))
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
