package avalara

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyAccount = "1234567890"
const dummyLicense = "abcdefABCDEF0123456789ab"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Avalara {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("AVALARA_ACCOUNT_ID=" + dummyAccount + "\nAVALARA_LICENSE=" + dummyLicense)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
	if string(res[0].RawV2) != dummyLicense {
		t.Errorf("RawV2 mismatch: %s", res[0].RawV2)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("ACCOUNT=" + dummyAccount + "\nLICENSE=" + dummyLicense)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// Regression: a high-entropy 24-char string sitting next to a bare prose
// mention of "avalara" (no assignment anchor) used to arm under the old
// strings.Contains(window,"avalara") radius-256 gate. The arm regex must now
// reject it.
func TestFromData_BareKeywordNoAnchor(t *testing.T) {
	body := []byte("We migrated our tax stack to avalara last quarter.\n" +
		"id=" + dummyAccount + "\nsecret=" + dummyLicense)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (no assignment anchor), got %d", len(res))
	}
}

// Regression: a credential pair more than 64 chars from any avalara reference
// must not arm under the tightened radius.
func TestFromData_OutOfRadius(t *testing.T) {
	pad := make([]byte, 200)
	for i := range pad {
		pad[i] = ' '
	}
	body := []byte("AVALARA_ACCOUNT_ID=" + dummyAccount + string(pad) +
		dummyLicense)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (license out of radius), got %d", len(res))
	}
}

// Regression: a low-entropy license-shaped token near the anchor is rejected
// by the entropy floor even though it matches the length/charset regex.
func TestFromData_LowEntropyLicenseRejected(t *testing.T) {
	body := []byte("AVALARA_ACCOUNT_ID=" + dummyAccount +
		"\nAVALARA_LICENSE=aaaaaaaaaaaaaaaaaaaaaaaa")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low-entropy license), got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		if u != dummyAccount || p != dummyLicense {
			t.Errorf("basic-auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyAccount+":"+dummyLicense)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyAccount+":"+dummyLicense)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyAccount+":"+dummyLicense)
	if v {
		t.Fatal("expected verified=false")
	}
}
