//go:build detector_unit

package sumologic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyID = "suABCDEFGHIJKL"
const dummyKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestFromData_Pair(t *testing.T) {
	body := []byte("SUMOLOGIC_ACCESS_ID=" + dummyID + "\nSUMOLOGIC_ACCESS_KEY=" + dummyKey)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyID {
		t.Fatalf("Raw mismatch: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != dummyKey {
		t.Fatalf("RawV2 mismatch: %q", res[0].RawV2)
	}
	if res[0].Severity != detectors.SeverityCritical {
		t.Fatalf("expected SeverityCritical")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("X=" + dummyID + "\nY=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_LowEntropyKeyRejected asserts the post-hardening behaviour:
// a valid-shaped access ID near the keyword but paired only with a
// low-entropy 64-char run (a placeholder, not a real base62 key) yields no
// key pairing. The ID alone still surfaces, but RawV2 stays empty.
func TestFromData_LowEntropyKeyRejected(t *testing.T) {
	// 64 chars but a single repeated character: entropy ~0, well under 3.5.
	lowEntropyKey := strings.Repeat("a", 64)
	body := []byte("SUMOLOGIC_ACCESS_ID=" + dummyID + "\nSUMOLOGIC_ACCESS_KEY=" + lowEntropyKey)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 result (id only), got %d", len(res))
	}
	if len(res[0].RawV2) != 0 {
		t.Fatalf("expected low-entropy key to be rejected, got RawV2=%q", res[0].RawV2)
	}
}

// TestFromData_BareKeywordNoArm asserts the radius/arm-regex tightening: a
// well-shaped ID + key sitting near a bare "sumo" mention that is NOT an
// assignment-style reference (e.g. prose) no longer arms the detector.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("we evaluated sumo and other vendors today\nX=" + dummyID + "\nY=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (bare prose keyword should not arm), got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyID)
	if r == dummyID {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "suABCDEF") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != dummyID || p != dummyKey {
			t.Errorf("basic mismatch: %q %q ok=%v", u, p, ok)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummyKey)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummyKey)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummyKey)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}
