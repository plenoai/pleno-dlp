package pushover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyToken = "abcdefghijklmnopqrstuvwxyz1234"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Pushover {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("pushover_token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without pushover keyword, got %d", len(res))
	}
}

// TestFromData_BareKeywordProse is the FP regression: a high-entropy 30-char
// alphanumeric run sitting near the word "pushover" in prose, with no
// assignment-style arm (`pushover[...]:=`). Before hardening, the radius-256
// bare-substring gate armed on the word alone and this matched. The arm regex
// + radius 64 must now reject it.
func TestFromData_BareKeywordProse(t *testing.T) {
	body := []byte("We migrated our pushover notifications last week. Build hash X7kQ2mLp9rTvWbN4cZ8sHdF1gJ6yAq was green.")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for high-entropy run near bare prose keyword, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected confirms a 30-char run that clears the regex
// and an assignment arm but is low-information is dropped by the entropy floor.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("pushover_token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy token, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("pushover=" + dummyToken + "\npushover_app=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostFormValue("token") != dummyToken {
			t.Errorf("token form value missing")
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

func TestVerify_BadRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
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
