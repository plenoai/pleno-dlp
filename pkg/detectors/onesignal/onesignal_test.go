package onesignal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	// dummyLegacy is a syntactically valid lowercase-hex UUID (8-4-4-4-12),
	// the documented OneSignal legacy REST API key shape. High enough variety
	// to clear the 3.0 entropy floor. Not a real credential.
	dummyLegacy = "3f8a1c2b-9d4e-4a6f-8b1c-2e5d7a9f0b3c"
	dummyV2     = "os_v2_app_abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.OneSignal {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_LegacyFound(t *testing.T) {
	body := []byte("onesignal_rest_api_key=" + dummyLegacy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_V2Found(t *testing.T) {
	body := []byte("onesignal_api_key=" + dummyV2)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token=" + dummyLegacy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without onesignal arm reference, got %d", len(res))
	}
}

// TestFromData_BareKeywordRejected guards the radius/arm tightening: a bare
// "onesignal" substring (e.g. an SDK script URL) near a UUID must NOT arm —
// only an assignment-style `onesignal...(key|token|secret)` reference does.
func TestFromData_BareKeywordRejected(t *testing.T) {
	body := []byte("https://cdn.onesignal.com/sdks/web/v16/OneSignalSDK.page.js loaded " + dummyLegacy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare-keyword (non-assignment) context, got %d", len(res))
	}
}

// TestFromData_GenericHexUUIDRejected is the regression fixture for the FP
// shape this hardening now rejects: a generic hex UUID (request/trace id) that
// previously matched on a loose radius-256 bare-substring gate. It sits near
// the word "onesignal" but lacks an assignment-style reference, so it must not
// surface.
func TestFromData_GenericHexUUIDRejected(t *testing.T) {
	body := []byte(`{"service":"onesignal","request_id":"3f8a1c2b-9d4e-4a6f-8b1c-2e5d7a9f0b3c"}`)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for generic UUID without arm reference, got %d", len(res))
	}
}

// TestFromData_LowEntropyUUIDRejected guards the entropy floor: a structurally
// valid but all-zero placeholder UUID, even with an arm reference, is dropped.
func TestFromData_LowEntropyUUIDRejected(t *testing.T) {
	body := []byte("onesignal_rest_api_key=00000000-0000-0000-0000-000000000000")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for all-zero placeholder UUID, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("onesignal_api_key=" + dummyLegacy + "\nonesignal_rest_api_key=" + dummyLegacy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
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

	v, err := Scanner{}.Verify(context.Background(), dummyLegacy)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyLegacy)
	if v {
		t.Fatal("expected verified=false")
	}
}
