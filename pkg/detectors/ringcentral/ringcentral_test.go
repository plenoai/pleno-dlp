package ringcentral

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyID = "abcdef0123456789abcdef01ABCDEF"
const dummySecret = "fedcba9876543210fedcba98ABCDEF"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.RingCentral {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("RINGCENTRAL_CLIENT_ID=" + dummyID + "\nRINGCENTRAL_CLIENT_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
	if string(res[0].RawV2) != dummySecret {
		t.Errorf("RawV2 mismatch: %s", res[0].RawV2)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("CLIENT_ID=" + dummyID + "\nCLIENT_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_BareKeywordNoArm is the FP-hardening regression. Two
// high-entropy alnum runs sit within radius-64 of a bare "ringcentral"
// mention (an SDK reference / prose), but there is no assignment-style
// `ringcentral_*` arm. The old radius-256 strings.Contains gate matched
// this; the armRe gate must now reject it.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("// uses the ringcentral SDK; build hashes " + dummyID + " and " + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("bare-keyword-no-arm should not match, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected confirms the entropy floor culls
// repeated-char runs that clear the length+charset regex but are not
// credentials, even when armed by a real assignment reference.
func TestFromData_LowEntropyRejected(t *testing.T) {
	lowEnt := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 30 chars, entropy 0
	body := []byte("RINGCENTRAL_CLIENT_ID=" + lowEnt + "\nRINGCENTRAL_CLIENT_SECRET=" + lowEnt)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("low-entropy run should not match, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		if u != dummyID || p != dummySecret {
			t.Errorf("basic-auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false")
	}
}
