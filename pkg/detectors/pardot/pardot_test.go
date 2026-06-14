//go:build detector_unit

package pardot

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyBU = "0Uv0123456789ABCDE"
const dummyTok = "00D000000000abcXYZ123456789ABCDEFabcdef"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Pardot {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("PARDOT_BU=" + dummyBU + "\nPARDOT_TOKEN=" + dummyTok)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
	if string(res[0].RawV2) != dummyTok {
		t.Errorf("RawV2 mismatch: %s", res[0].RawV2)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("BU=" + dummyBU + "\nTOKEN=" + dummyTok)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_GenericHighEntropyRejected is the FP-hardening regression: two
// generic high-entropy alphanumeric strings sitting next to the `pardot`
// keyword no longer match. Real credentials are structurally anchored — the
// Business Unit ID begins with `0Uv` (18 chars) and the access token begins
// with `00D` — so a build-id / base64-blob pair that previously satisfied the
// bare `[A-Za-z0-9]{18,256}` + radius-256 keyword gate is now rejected.
func TestFromData_GenericHighEntropyRejected(t *testing.T) {
	body := []byte("pardot_api_token config\nfirst=Zk9Qm2Xc7VtRbN4hYpL8dWg3\nsecond=Jq6Tn1Bs5Hx0CwM8eRf2KdVa9")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (generic high-entropy strings must not match), got %d", len(res))
	}
}

// TestFromData_RealisticToken asserts recall on the documented live shape: a
// Salesforce OAuth access token (`00D<orgid>!<tail>` with `.`/`_` separators)
// paired with a `0Uv` Business Unit ID. The pre-hardening bare-alnum regex
// could not match this real token because it excluded `!`, `.` and `_`.
func TestFromData_RealisticToken(t *testing.T) {
	const realTok = "00DB0000000TfcRMAQ!AQQAQFhoK8vTMg_rKA.esrJ2bCs.OOIjJgl9Cx6O7Kqj"
	body := []byte("PARDOT_BUSINESS_UNIT_ID=" + dummyBU + "\nPARDOT_API_TOKEN=" + realTok)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1 for realistic Salesforce OAuth token")
	}
	if string(res[0].RawV2) != realTok {
		t.Errorf("RawV2 mismatch: %s", res[0].RawV2)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummyTok {
			t.Errorf("auth mismatch")
		}
		if r.Header.Get("Pardot-Business-Unit-Id") != dummyBU {
			t.Errorf("bu mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyBU+":"+dummyTok)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyBU+":"+dummyTok)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyBU+":"+dummyTok)
	if v {
		t.Fatal("expected verified=false")
	}
}
