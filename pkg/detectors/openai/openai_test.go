package openai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyKey = "sk-abcdefghijklmnopqrstuvwxyz0123456789"
const dummyProjKey = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDE"
const anthropicKey = "sk-ant-abcdefghijklmnopqrstuvwxyz0123456789"

func TestFromData_PositiveStandard(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("OPENAI_API_KEY="+dummyKey))
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_PositiveProject(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("key="+dummyProjKey))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_ExcludeAnthropic(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("key="+anthropicKey))
	if len(res) != 0 {
		t.Fatalf("expected 0 (anthropic must not match openai), got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("nothing here"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummyKey {
			t.Errorf("auth header mismatch: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyKey)
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

	v, err := Scanner{}.Verify(context.Background(), dummyKey)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false on 401")
	}
}

func TestKeyKind(t *testing.T) {
	cases := map[string]string{
		"sk-abcdef":                          "legacy-user",
		"sk-proj-abcdef":                     "project",
		"sk-svcacct-abcdef":                  "service-account",
		"sk-admin-abcdef":                    "admin",
		"random":                             "unknown",
	}
	for in, want := range cases {
		if got := keyKind(in); got != want {
			t.Errorf("keyKind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFromData_KeyKindAlwaysSet(t *testing.T) {
	cases := map[string]string{
		dummyKey:     "legacy-user",
		dummyProjKey: "project",
	}
	for tok, want := range cases {
		res, _ := Scanner{}.FromData(context.Background(), false, []byte(tok))
		if len(res) != 1 {
			t.Fatalf("token=%q expected 1 result, got %d", tok, len(res))
		}
		if got := res[0].ExtraData["openai_key_kind"]; got != want {
			t.Errorf("token=%q openai_key_kind=%q, want %q", tok, got, want)
		}
	}
}

func TestFromData_LegacyKeyMarkedPrivileged(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(dummyKey))
	if res[0].ExtraData["openai_privileged"] != "true" {
		t.Errorf("legacy-user key must be marked openai_privileged=true")
	}
}

func TestFromData_ProjectKeyNotPrivileged(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(dummyProjKey))
	if _, ok := res[0].ExtraData["openai_privileged"]; ok {
		t.Errorf("project-scoped key must NOT carry openai_privileged")
	}
}

func TestFromData_VerifyEnrichesFromModelsList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("expected /v1/models, got %s", r.URL.Path)
		}
		w.Header().Set("openai-organization", "org-acmecorp")
		_, _ = w.Write([]byte(`{"object":"list","data":[
		  {"id":"gpt-4o","owned_by":"openai"},
		  {"id":"gpt-4-turbo","owned_by":"openai"},
		  {"id":"o1-preview","owned_by":"openai"},
		  {"id":"dall-e-3","owned_by":"openai"},
		  {"id":"text-embedding-3-large","owned_by":"openai"},
		  {"id":"some-fine-tune::abc","owned_by":"org"}
		]}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte(dummyKey))
	if !res[0].Verified {
		t.Fatalf("expected Verified=true")
	}
	want := map[string]string{
		"openai_key_kind":     "legacy-user",
		"openai_privileged":   "true",
		"openai_organization": "org-acmecorp",
		"openai_models_count": "6",
	}
	for k, v := range want {
		if res[0].ExtraData[k] != v {
			t.Errorf("ExtraData[%q] = %q, want %q", k, res[0].ExtraData[k], v)
		}
	}
	notable := res[0].ExtraData["openai_notable_models"]
	for _, must := range []string{"gpt-4o", "gpt-4-turbo", "o1", "dall-e-3", "text-embedding-3-large"} {
		if !strings.Contains(notable, must) {
			t.Errorf("openai_notable_models %q missing %q", notable, must)
		}
	}
}

func TestFromData_VerifyHandlesEmptyModelsList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	res, _ := Scanner{}.FromData(context.Background(), true, []byte(dummyKey))
	if !res[0].Verified {
		t.Fatalf("expected Verified=true even with empty data")
	}
	if res[0].ExtraData["openai_models_count"] != "0" {
		t.Errorf("openai_models_count = %q, want 0", res[0].ExtraData["openai_models_count"])
	}
	if _, ok := res[0].ExtraData["openai_notable_models"]; ok {
		t.Errorf("openai_notable_models must be absent when no notable hits")
	}
}
