//go:build detector_unit

package stripe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyLive = "sk_live_abcdefghijklmnopqrstu"
const dummyTest = "sk_test_abcdefghijklmnopqrstu"
const dummyRk = "rk_live_abcdefghijklmnopqrstu"

func TestFromData_PositiveLive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("STRIPE_KEY="+dummyLive))
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_PositiveTest(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(dummyTest))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_PositiveRestricted(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(dummyRk))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("nothing here"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyLive)
	if !strings.HasPrefix(r, "sk_live_") {
		t.Fatalf("redact missing prefix: %q", r)
	}
	if strings.Contains(r, "qrstu") {
		t.Fatalf("redact leaked tail: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummyLive {
			t.Errorf("auth header mismatch: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyLive)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
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

	v, err := Scanner{}.Verify(context.Background(), dummyLive)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false on 401")
	}
}

func TestFromData_KeyModeAlwaysSet(t *testing.T) {
	cases := map[string]string{
		dummyLive: "live",
		dummyTest: "test",
		dummyRk:   "restricted-live",
	}
	for tok, want := range cases {
		res, _ := Scanner{}.FromData(context.Background(), false, []byte(tok))
		if got := res[0].ExtraData["stripe_key_mode"]; got != want {
			t.Errorf("token=%q stripe_key_mode=%q, want %q", tok, got, want)
		}
	}
}

func TestFromData_VerifyEnrichesAccount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/account" {
			t.Errorf("expected /v1/account, got %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
		  "id": "acct_1ABCDEXyz",
		  "country": "US",
		  "default_currency": "usd",
		  "display_name": "Acme",
		  "livemode": true,
		  "charges_enabled": true,
		  "payouts_enabled": true,
		  "business_profile": {"name": "Acme Corp"}
		}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte(dummyLive))
	if !res[0].Verified {
		t.Errorf("expected Verified=true")
	}
	want := map[string]string{
		"stripe_account_id":       "acct_1ABCDEXyz",
		"stripe_business_name":    "Acme Corp",
		"stripe_country":          "US",
		"stripe_default_currency": "usd",
		"stripe_livemode":         "true",
		"stripe_charges_enabled":  "true",
		"stripe_payouts_enabled":  "true",
		"stripe_high_value":       "true",
		"stripe_key_mode":         "live",
	}
	for k, v := range want {
		if res[0].ExtraData[k] != v {
			t.Errorf("ExtraData[%q] = %q, want %q", k, res[0].ExtraData[k], v)
		}
	}
}

func TestFromData_VerifyTestKeyNotHighValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
		  "id": "acct_test",
		  "livemode": false,
		  "charges_enabled": true,
		  "payouts_enabled": true
		}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte(dummyTest))
	if _, ok := res[0].ExtraData["stripe_high_value"]; ok {
		t.Errorf("test-mode key must never be high_value")
	}
	if _, ok := res[0].ExtraData["stripe_livemode"]; ok {
		t.Errorf("livemode flag should be absent on test key")
	}
}

func TestVerify_RestrictedKeyForbiddenFallsBackToCharges(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/account":
			w.WriteHeader(http.StatusForbidden)
		case "/v1/charges":
			_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyRk)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Errorf("restricted key should still verify via charges fallback")
	}
}

func TestKeyMode(t *testing.T) {
	cases := map[string]string{
		"sk_live_x": "live",
		"sk_test_x": "test",
		"rk_live_x": "restricted-live",
		"rk_test_x": "restricted-test",
		"random":    "unknown",
	}
	for in, want := range cases {
		if got := keyMode(in); got != want {
			t.Errorf("keyMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if firstNonEmpty("", "second", "third") != "second" {
		t.Error("expected second")
	}
	if firstNonEmpty("first", "second") != "first" {
		t.Error("expected first")
	}
	if firstNonEmpty("", "") != "" {
		t.Error("expected empty")
	}
}
