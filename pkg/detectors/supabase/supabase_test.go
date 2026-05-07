package supabase

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func mintJWT(t *testing.T, claims map[string]string) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body, _ := json.Marshal(claims)
	pl := base64.RawURLEncoding.EncodeToString(body)
	sig := base64.RawURLEncoding.EncodeToString([]byte("padding-padding-padding-bytes-bytes-bytes"))
	return hdr + "." + pl + "." + sig
}

func TestFromData_ServiceRole_Critical(t *testing.T) {
	tok := mintJWT(t, map[string]string{
		"role": "service_role",
		"ref":  "abcdefghijklmnopqrst",
		"iss":  "supabase",
	})
	body := []byte("# supabase\nSUPABASE_SERVICE_ROLE_KEY=" + tok + "\nSUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co")
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Severity != detectors.SeverityCritical {
		t.Fatalf("expected SeverityCritical for service_role, got %v", res[0].Severity)
	}
	if res[0].ExtraData["role"] != "service_role" {
		t.Fatalf("role mismatch: %q", res[0].ExtraData["role"])
	}
	if res[0].ExtraData["project_ref"] != "abcdefghijklmnopqrst" {
		t.Fatalf("project_ref capture missing: %q", res[0].ExtraData["project_ref"])
	}
}

func TestFromData_AnonKey_High(t *testing.T) {
	tok := mintJWT(t, map[string]string{
		"role": "anon",
		"ref":  "abcdefghijklmnopqrst",
	})
	body := []byte("# supabase\nNEXT_PUBLIC_SUPABASE_ANON_KEY=" + tok)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Severity == detectors.SeverityCritical {
		t.Fatalf("anon key should not be Critical, got %v", res[0].Severity)
	}
}

func TestFromData_NotSupabase(t *testing.T) {
	tok := mintJWT(t, map[string]string{
		"sub": "111",
		"iss": "https://accounts.google.com",
	})
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("# supabase\nX="+tok))
	if len(res) != 0 {
		t.Fatalf("non-supabase JWT must not be claimed; got %d", len(res))
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	tok := mintJWT(t, map[string]string{
		"role": "service_role",
	})
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+tok))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	tok := mintJWT(t, map[string]string{"role": "service_role"})
	r := redact(tok)
	if r == tok {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "eyJ") {
		t.Fatalf("missing prefix: %q", r)
	}
}
