package twilio

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummySID = "AC0123456789abcdef0123456789abcdef"
const dummyToken = "fedcba9876543210fedcba9876543210"

func TestFromData_Pair(t *testing.T) {
	body := []byte("TWILIO_SID=" + dummySID + "\nTWILIO_TOKEN=" + dummyToken)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].RawV2) != dummyToken {
		t.Fatalf("RawV2 mismatch: %q", res[0].RawV2)
	}
}

func TestFromData_SIDOnly(t *testing.T) {
	body := []byte("TWILIO_SID=" + dummySID)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if len(res[0].RawV2) != 0 {
		t.Fatalf("RawV2 should be empty: %q", res[0].RawV2)
	}
	if res[0].Verified {
		t.Fatal("single key must not be verified")
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummySID)
	if !strings.HasPrefix(r, "AC") {
		t.Fatalf("missing prefix: %q", r)
	}
	if strings.Contains(r, "abcdef") {
		t.Fatalf("redact leaked: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != dummySID || p != dummyToken {
			t.Errorf("basic auth mismatch")
		}
		if !strings.Contains(r.URL.Path, dummySID) {
			t.Errorf("path missing sid: %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummySID+":"+dummyToken)
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

	v, err := Scanner{}.Verify(context.Background(), dummySID+":"+dummyToken)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestFromData_VerifyEnrichesFullActive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
		  "friendly_name": "Acme Production",
		  "status": "active",
		  "type": "Full",
		  "owner_account_sid": "` + dummySID + `",
		  "date_created": "Mon, 01 Jan 2024 00:00:00 +0000"
		}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	body := []byte("TWILIO_SID=" + dummySID + "\nTWILIO_TOKEN=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), true, body)
	if !res[0].Verified {
		t.Fatalf("expected Verified=true")
	}
	want := map[string]string{
		"twilio_friendly_name":  "Acme Production",
		"twilio_account_status": "active",
		"twilio_account_type":   "Full",
		"twilio_high_value":     "true",
	}
	for k, v := range want {
		if res[0].ExtraData[k] != v {
			t.Errorf("ExtraData[%q] = %q, want %q", k, res[0].ExtraData[k], v)
		}
	}
	if _, ok := res[0].ExtraData["twilio_subaccount"]; ok {
		t.Errorf("twilio_subaccount must be absent when owner == sid")
	}
	if _, ok := res[0].ExtraData["twilio_owner_sid"]; ok {
		t.Errorf("twilio_owner_sid must be absent when owner == sid")
	}
}

func TestFromData_VerifyTrialNotHighValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
		  "friendly_name": "demo",
		  "status": "active",
		  "type": "Trial",
		  "owner_account_sid": "` + dummySID + `"
		}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	body := []byte(dummySID + " " + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), true, body)
	if !res[0].Verified {
		t.Fatalf("expected Verified=true")
	}
	if _, ok := res[0].ExtraData["twilio_high_value"]; ok {
		t.Errorf("Trial account must never be high_value")
	}
	if res[0].ExtraData["twilio_account_type"] != "Trial" {
		t.Errorf("twilio_account_type = %q, want Trial", res[0].ExtraData["twilio_account_type"])
	}
}

func TestFromData_VerifyInactiveNotHighValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
		  "status": "suspended",
		  "type": "Full"
		}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	body := []byte(dummySID + " " + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), true, body)
	if _, ok := res[0].ExtraData["twilio_high_value"]; ok {
		t.Errorf("suspended Full account must not be high_value")
	}
	if res[0].ExtraData["twilio_account_status"] != "suspended" {
		t.Errorf("twilio_account_status = %q, want suspended", res[0].ExtraData["twilio_account_status"])
	}
}

func TestFromData_VerifySubaccountFlagged(t *testing.T) {
	const parentSID = "ACfedcba9876543210fedcba9876543210"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
		  "friendly_name": "sub",
		  "status": "active",
		  "type": "Full",
		  "owner_account_sid": "` + parentSID + `"
		}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	body := []byte(dummySID + " " + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), true, body)
	if res[0].ExtraData["twilio_subaccount"] != "true" {
		t.Errorf("expected twilio_subaccount=true")
	}
	if res[0].ExtraData["twilio_owner_sid"] != parentSID {
		t.Errorf("twilio_owner_sid = %q, want %q", res[0].ExtraData["twilio_owner_sid"], parentSID)
	}
}

func TestIsHighRisk(t *testing.T) {
	cases := []struct {
		accType, status string
		want            bool
	}{
		{"Full", "active", true},
		{"full", "ACTIVE", true},
		{"Full", "suspended", false},
		{"Trial", "active", false},
		{"Full", "closed", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := isHighRisk(c.accType, c.status); got != c.want {
			t.Errorf("isHighRisk(%q,%q) = %v, want %v", c.accType, c.status, got, c.want)
		}
	}
}
