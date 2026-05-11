package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func makeJWT(t *testing.T, header, claims map[string]interface{}) string {
	t.Helper()
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	return enc(hb) + "." + enc(cb) + ".sig" + enc([]byte("0123456789"))
}

func TestFromData_Positive(t *testing.T) {
	tok := makeJWT(t,
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"iss": "issuer.example", "sub": "user-123"},
	)
	res, err := Scanner{}.FromData(context.Background(), false, []byte("Authorization: Bearer "+tok))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].ExtraData["iss"] != "issuer.example" {
		t.Fatalf("iss not extracted: %+v", res[0].ExtraData)
	}
	if res[0].ExtraData["sub"] != "user-123" {
		t.Fatalf("sub not extracted: %+v", res[0].ExtraData)
	}
	if res[0].ExtraData["alg"] != "HS256" {
		t.Fatalf("alg not extracted: %+v", res[0].ExtraData)
	}
	if res[0].Verified {
		t.Fatal("JWT must never be Verified=true (no key material)")
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("not-a-jwt"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_AlgNone_PinsCritical(t *testing.T) {
	tok := makeJWT(t,
		map[string]interface{}{"alg": "none", "typ": "JWT"},
		map[string]interface{}{"sub": "user-1"},
	)
	res, err := Scanner{}.FromData(context.Background(), false, []byte(tok))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res[0].Severity != detectors.SeverityCritical {
		t.Errorf("alg=none must be Critical, got %v", res[0].Severity)
	}
	if res[0].ExtraData["jwt_alg_none"] != "true" {
		t.Errorf("jwt_alg_none flag missing: %+v", res[0].ExtraData)
	}
}

func TestFromData_Expired_DowngradesToLow(t *testing.T) {
	prev := nowFunc
	nowFunc = func() time.Time { return time.Unix(2_000_000_000, 0) }
	t.Cleanup(func() { nowFunc = prev })

	tok := makeJWT(t,
		map[string]interface{}{"alg": "HS256"},
		map[string]interface{}{"sub": "u", "exp": float64(1_000_000_000)},
	)
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(tok))
	if res[0].Severity != detectors.SeverityLow {
		t.Errorf("expired token should be Low, got %v", res[0].Severity)
	}
	if res[0].ExtraData["jwt_status"] != "expired" {
		t.Errorf("jwt_status = %q, want expired", res[0].ExtraData["jwt_status"])
	}
}

func TestFromData_Active_PinsHigh(t *testing.T) {
	prev := nowFunc
	nowFunc = func() time.Time { return time.Unix(1_000_000_000, 0) }
	t.Cleanup(func() { nowFunc = prev })

	tok := makeJWT(t,
		map[string]interface{}{"alg": "HS256"},
		map[string]interface{}{"sub": "u", "exp": float64(2_000_000_000)},
	)
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(tok))
	if res[0].Severity != detectors.SeverityHigh {
		t.Errorf("active token should be High, got %v", res[0].Severity)
	}
	if res[0].ExtraData["jwt_status"] != "active" {
		t.Errorf("jwt_status = %q, want active", res[0].ExtraData["jwt_status"])
	}
}

func TestFromData_AlgNoneBeatsActiveExp(t *testing.T) {
	prev := nowFunc
	nowFunc = func() time.Time { return time.Unix(1_000_000_000, 0) }
	t.Cleanup(func() { nowFunc = prev })

	tok := makeJWT(t,
		map[string]interface{}{"alg": "none"},
		map[string]interface{}{"exp": float64(2_000_000_000)},
	)
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(tok))
	if res[0].Severity != detectors.SeverityCritical {
		t.Errorf("alg=none must override exp severity, got %v", res[0].Severity)
	}
}

func TestFromData_IssuerClassification(t *testing.T) {
	cases := map[string]string{
		"https://token.actions.githubusercontent.com": "github-actions-oidc",
		"https://accounts.google.com":                 "google",
		"https://acme.auth0.com/":                     "auth0",
		"https://acme.okta.com":                       "okta",
		"https://securetoken.google.com/p-123":        "firebase",
		"https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEf123": "aws-cognito",
		"https://login.microsoftonline.com/tid/v2.0":  "azure-ad",
	}
	for iss, want := range cases {
		tok := makeJWT(t,
			map[string]interface{}{"alg": "RS256"},
			map[string]interface{}{"iss": iss},
		)
		res, _ := Scanner{}.FromData(context.Background(), false, []byte(tok))
		if got := res[0].ExtraData["issuer_class"]; got != want {
			t.Errorf("iss=%q → issuer_class=%q, want %q", iss, got, want)
		}
	}
}

func TestFromData_ScopeClaim_String(t *testing.T) {
	tok := makeJWT(t,
		map[string]interface{}{"alg": "RS256"},
		map[string]interface{}{"scope": "read:user write:repo"},
	)
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(tok))
	if res[0].ExtraData["scope"] != "read:user,write:repo" {
		t.Errorf("scope = %q, want comma-joined", res[0].ExtraData["scope"])
	}
}

func TestFromData_ScopeClaim_Array(t *testing.T) {
	tok := makeJWT(t,
		map[string]interface{}{"alg": "RS256"},
		map[string]interface{}{"scopes": []interface{}{"admin", "billing"}},
	)
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(tok))
	if res[0].ExtraData["scope"] != "admin,billing" {
		t.Errorf("scope = %q, want admin,billing", res[0].ExtraData["scope"])
	}
}

func TestFromData_AudClaim_Array(t *testing.T) {
	tok := makeJWT(t,
		map[string]interface{}{"alg": "RS256"},
		map[string]interface{}{"aud": []interface{}{"api1", "api2"}},
	)
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(tok))
	if res[0].ExtraData["aud"] != "api1,api2" {
		t.Errorf("aud = %q, want comma-joined", res[0].ExtraData["aud"])
	}
}

func TestFromData_KidExposed(t *testing.T) {
	tok := makeJWT(t,
		map[string]interface{}{"alg": "RS256", "kid": "key-2024-01"},
		map[string]interface{}{"sub": "u"},
	)
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(tok))
	if res[0].ExtraData["kid"] != "key-2024-01" {
		t.Errorf("kid missing: %+v", res[0].ExtraData)
	}
}

func TestRedact(t *testing.T) {
	tok := makeJWT(t, map[string]interface{}{"alg": "none"}, map[string]interface{}{"x": 1})
	r := redact(tok)
	if !strings.HasPrefix(r, "eyJ") {
		t.Fatalf("missing prefix: %q", r)
	}
	if r == tok {
		t.Fatalf("redact didn't redact")
	}
}
