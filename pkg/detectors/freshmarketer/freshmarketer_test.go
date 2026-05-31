package freshmarketer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "ABCDEFGHIJKLmnopqrstuvwxyz012345"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Freshmarketer {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("FRESHMARKETER_API_KEY=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED_VALUE=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_BareMentionNoArm guards the radius/arm tightening: a high-entropy
// alnum token sitting near a prose mention of "freshmarketer" (no assignment-style
// api/key/token/secret reference) must NOT arm any more. This is the FP shape the
// old radius-256 strings.Contains gate accepted.
func TestFromData_BareMentionNoArm(t *testing.T) {
	body := []byte("freshmarketer is a marketing tool. random id " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (bare mention should not arm), got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected guards the entropy floor: an armed but
// low-variety alnum string must be rejected.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("freshmarketer_api_key=aaaaaaaaaaaaaaaaaaaaaa")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low entropy should be rejected), got %d", len(res))
	}
}

// TestFromData_FarFromKeyword guards the radius shrink: a valid-shaped token
// more than 64 chars away from the keyword must not arm.
func TestFromData_FarFromKeyword(t *testing.T) {
	gap := make([]byte, 80)
	for i := range gap {
		gap[i] = ' '
	}
	body := []byte("freshmarketer_api_key:" + string(gap) + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (token beyond radius), got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token token="+dummy {
			t.Errorf("missing token auth")
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
	v, _ := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false")
	}
}
