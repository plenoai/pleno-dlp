package fastspring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyUser = "abcdef0123456789ABCDEF"
const dummyPass = "ZYXWVU9876543210zyxwvu"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.FastSpring {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("FASTSPRING_USER=" + dummyUser + "\nFASTSPRING_PASSWORD=" + dummyPass)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("USER=" + dummyUser + "\nPASS=" + dummyPass)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without fastspring keyword, got %d", len(res))
	}
}

// TestFromData_BareKeywordNoArm guards the radius-256 -> arm-regex tightening:
// a bare "fastspring" mention (a doc link, the api host) near two generic
// high-entropy alphanumeric runs must NOT arm without an assignment-style
// `fastspring_user` / `fastspring_password` reference.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("// see https://api.fastspring.com docs\n" +
		"id=" + dummyUser + "\nsecret=" + dummyPass)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("bare fastspring keyword should not arm without assignment anchor, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected guards the entropy floor: a padded, low-
// information run that clears the {16,32} alnum regex and sits next to a real
// `fastspring_user` reference must still be rejected.
func TestFromData_LowEntropyRejected(t *testing.T) {
	lowEntropy := "AAAAAAAAAAAAAAAAAAAA" // 20 identical chars: entropy ~0
	body := []byte("FASTSPRING_USER=" + lowEntropy + "\nFASTSPRING_PASSWORD=" + lowEntropy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("low-entropy run should be rejected, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		if u != dummyUser || p != dummyPass {
			t.Errorf("auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyUser+":"+dummyPass)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyUser+":"+dummyPass)
	if v {
		t.Fatal("expected verified=false")
	}
}
