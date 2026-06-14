//go:build detector_unit

package sentry

import (
	"context"
	"strings"
	"testing"
)

const dummy = "https://0123456789abcdef0123456789abcdef@o12345.ingest.sentry.io/4504000"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), true, []byte("SENTRY_DSN="+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	// Verify must always be false — we never call out to Sentry.
	if res[0].Verified {
		t.Fatal("Sentry DSNs are unverified-by-design; got Verified=true")
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_Negative(t *testing.T) {
	// Missing project id slug, no @, etc.
	cases := [][]byte{
		[]byte("https://abc@sentry.io"),
		[]byte("https://0123456789abcdef0123456789abcdef@/123"),
		[]byte("not a dsn"),
	}
	for i, c := range cases {
		res, _ := Scanner{}.FromData(context.Background(), false, c)
		if len(res) != 0 {
			t.Fatalf("case %d: expected 0, got %d", i, len(res))
		}
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "https://") {
		t.Fatalf("missing scheme: %q", r)
	}
}
