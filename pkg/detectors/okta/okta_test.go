package okta

import (
	"context"
	"strings"
	"testing"
)

// 00 + 40 URL-safe chars.
const dummy = "00aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCd"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("OKTA_API_TOKEN="+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Verified {
		t.Fatal("Okta tokens are unverified-by-design (need tenant URL); got Verified=true")
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("00short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "00aBcD") {
		t.Fatalf("missing prefix: %q", r)
	}
}
