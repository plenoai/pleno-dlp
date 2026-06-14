//go:build detector_unit

package sageintacct

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "P@ssw0rd1234567890ABCabc"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.SageIntacct {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("INTACCT_SENDER_PASSWORD=" + dummy)
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

// TestFromData_BareKeywordNoArm guards the radius/arm-regex tightening. A
// generic high-entropy alnum run sitting near a bare "intacct" mention (a doc
// link, a package path) without an assignment-style credential reference must
// NOT match: pre-hardening the radius-256 strings.Contains gate fired on this
// shape; post-hardening the armRe gate rejects it.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("see https://developer.intacct.com/docs for details X9kQ2mPv7Lr4Zt6Wn3Bc8Df")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (bare keyword, no assignment anchor), got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected guards the entropy floor: a padded /
// repeated-character run clears the alnum regex and sits next to a real
// assignment anchor, but must be culled by HasMinEntropy.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("INTACCT_SENDER_PASSWORD=aaaaaaaaaaaaaaaa")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low-entropy run), got %d", len(res))
	}
}

// TestFromData_ArmedStillDetects pins recall after tightening: a realistic
// provisioned-style value next to the assignment anchor must still fire.
func TestFromData_ArmedStillDetects(t *testing.T) {
	body := []byte("intacct_sender_password = " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1 (armed assignment), recall regression")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

func TestVerify_NoApiBase(t *testing.T) {
	old := apiBase
	apiBase = ""
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil || v {
		t.Fatalf("expected unverified no-error, got v=%v err=%v", v, err)
	}
}
