//go:build detector_unit

package cloudflare

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyTok = "abcdefghijklmnopqrstuvwxyz0123456789ABCD"

func TestFromData_PositiveWithKeyword(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("CF_API_TOKEN="+dummyTok))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_NoKeywordSuppressed(t *testing.T) {
	// Same shape, no co-occurrence: must NOT emit (otherwise we drown in noise).
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("FOO="+dummyTok))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyTok)
	if !strings.HasPrefix(r, dummyTok[:6]) {
		t.Fatalf("redact prefix wrong: %q", r)
	}
	if strings.Contains(r, "0123456789ABCD") {
		t.Fatalf("redact leaked tail: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummyTok {
			t.Errorf("auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyTok)
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

	v, err := Scanner{}.Verify(context.Background(), dummyTok)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestFromData_VerifyEnrichesTokenAndAccounts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/client/v4/user/tokens/verify":
			_, _ = w.Write([]byte(`{
			  "result":{
			    "id":"ed17574386854bf78a67040be0a770b0",
			    "status":"active",
			    "not_before":"2024-01-01T00:00:00Z",
			    "expires_on":"2026-12-31T00:00:00Z"
			  },
			  "success":true,
			  "errors":[],
			  "messages":[{"code":10000,"message":"This API Token is valid and active"}]
			}`))
		case "/client/v4/accounts":
			_, _ = w.Write([]byte(`{
			  "result":[
			    {"id":"acc1","name":"Acme Corp"},
			    {"id":"acc2","name":"Acme Subsidiary"}
			  ],
			  "success":true
			}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte("CF_API_TOKEN="+dummyTok))
	if !res[0].Verified {
		t.Fatalf("expected Verified=true")
	}
	want := map[string]string{
		"cf_token_id":         "ed17574386854bf78a67040be0a770b0",
		"cf_token_status":     "active",
		"cf_token_expires_on": "2026-12-31T00:00:00Z",
		"cf_token_not_before": "2024-01-01T00:00:00Z",
		"cf_accounts_count":   "2",
		"cf_account_names":    "Acme Corp,Acme Subsidiary",
	}
	for k, v := range want {
		if res[0].ExtraData[k] != v {
			t.Errorf("ExtraData[%q] = %q, want %q", k, res[0].ExtraData[k], v)
		}
	}
	if _, ok := res[0].ExtraData["cf_token_inactive"]; ok {
		t.Errorf("active token must not be marked inactive")
	}
}

func TestFromData_VerifyDisabledTokenFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/client/v4/user/tokens/verify":
			_, _ = w.Write([]byte(`{"result":{"id":"x","status":"disabled"},"success":true}`))
		case "/client/v4/accounts":
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte("CF_API_TOKEN="+dummyTok))
	if !res[0].Verified {
		t.Fatalf("expected Verified=true (verify endpoint returned 200)")
	}
	if res[0].ExtraData["cf_token_status"] != "disabled" {
		t.Errorf("cf_token_status = %q, want disabled", res[0].ExtraData["cf_token_status"])
	}
	if res[0].ExtraData["cf_token_inactive"] != "true" {
		t.Errorf("disabled token must be marked cf_token_inactive=true")
	}
	if _, ok := res[0].ExtraData["cf_accounts_count"]; ok {
		t.Errorf("cf_accounts_count must be absent when /accounts returns 403")
	}
}

func TestFromData_VerifyTruncatesLongAccountList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/client/v4/user/tokens/verify":
			_, _ = w.Write([]byte(`{"result":{"id":"x","status":"active"},"success":true}`))
		case "/client/v4/accounts":
			_, _ = w.Write([]byte(`{"result":[
			  {"id":"1","name":"A"},{"id":"2","name":"B"},{"id":"3","name":"C"},
			  {"id":"4","name":"D"},{"id":"5","name":"E"},{"id":"6","name":"F"},
			  {"id":"7","name":"G"}
			],"success":true}`))
		}
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte("CF_API_TOKEN="+dummyTok))
	if res[0].ExtraData["cf_accounts_count"] != "7" {
		t.Errorf("cf_accounts_count = %q, want 7", res[0].ExtraData["cf_accounts_count"])
	}
	names := res[0].ExtraData["cf_account_names"]
	if !strings.HasSuffix(names, ",…") {
		t.Errorf("expected names to be truncated with …, got %q", names)
	}
	if strings.Count(names, ",") != 5 {
		t.Errorf("expected 5 commas (5 names + truncation marker), got %d: %q",
			strings.Count(names, ","), names)
	}
}
