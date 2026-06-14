//go:build detector_unit

package oraclecloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "abcdefABCDEF0123456789abcdefABCDEF01234567"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.OracleCloud {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("OCI_TENANCY_KEY=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_OcidPrefixArms covers the distinctive `ocid1.` OCID marker as an
// assignment-anchor, alongside an Auth-Token-shaped value.
func TestFromData_OcidPrefixArms(t *testing.T) {
	body := []byte("resource = ocid1.tenancy.oc1..aaaa region\ntoken = " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1 when ocid1. marker is within window")
	}
}

// TestFromData_BareKeywordRejected is the FP-shape regression. A generic
// high-entropy 42-char run sitting near a BARE "oraclecloud" word (a doc/comment
// mention, not an assignment) used to match under the radius-256 Contains gate.
// The tightened arm regex + radius 64 must now reject it.
func TestFromData_BareKeywordRejected(t *testing.T) {
	body := []byte("// see the oraclecloud blog post. build id: " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (bare-keyword FP shape), got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected covers the conservative entropy floor: a
// repetitive 42-char run in a valid assignment context is still culled.
func TestFromData_LowEntropyRejected(t *testing.T) {
	lowEntropy := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 42x 'a'
	body := []byte("OCI_AUTH_TOKEN=" + lowEntropy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low-entropy), got %d", len(res))
	}
}

func TestVerify_Disabled_Default(t *testing.T) {
	v, _ := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false default")
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
