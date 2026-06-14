//go:build detector_unit

package upstashredis

import (
	"context"
	"strings"
	"testing"
)

// dummy is a realistic-shaped Upstash REST token: high-entropy base64url
// with a mix of lower/upper/digit (never a real credential).
const dummy = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUv"

func TestFromData_Positive(t *testing.T) {
	body := []byte("# upstash\nUPSTASH_REDIS_REST_TOKEN=" + dummy + "\nUPSTASH_REDIS_REST_URL=https://us1-test-12345.upstash.io")
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) == 0 {
		t.Fatalf("expected at least 1, got %d", len(res))
	}
	var found bool
	for _, r := range res {
		if string(r.Raw) == dummy {
			found = true
			if got := r.ExtraData["host"]; got != "us1-test-12345.upstash.io" {
				t.Fatalf("expected host capture, got %q", got)
			}
		}
	}
	if !found {
		t.Fatalf("expected dummy token in results: %+v", res)
	}
}

// True positive on the canonical assignment even without a nearby host:
// host binding is optional, the assignment context is enough.
func TestFromData_Positive_NoHost(t *testing.T) {
	body := []byte(`UPSTASH_REDIS_REST_TOKEN="` + dummy + `"`)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("wrong token: %q", res[0].Raw)
	}
	if h := res[0].ExtraData["host"]; h != "" {
		t.Fatalf("expected no host, got %q", h)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

// FP #1: a 64-char lowercase hex sha256/commit digest sitting next to an
// `@upstash/redis` dependency line (e.g. a lockfile integrity hash). It is
// all-hex (no upper, no digit-diversity beyond hex) and is now rejected by
// the hex-exclusion + character-diversity gate.
func TestFromData_FP_HexDigestNearUpstashDep(t *testing.T) {
	hex := "a3f9c1d2b4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f"
	body := []byte("# @upstash/redis@1.2.3\n# integrity sha256-" + hex + "\n")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	for _, r := range res {
		if string(r.Raw) == hex {
			t.Fatalf("hex digest near upstash dep should be suppressed, got %+v", r)
		}
	}
	if len(res) != 0 {
		t.Fatalf("expected 0 results, got %d: %+v", len(res), res)
	}
}

// FP #2: an unrelated vendor key (high-entropy but no Upstash context within
// the tight 64-byte radius) that previously matched because the chunk
// mentioned UPSTASH_REDIS_REST_URL somewhere within 256 bytes. With the
// radius shrunk to 64 and bound to Upstash-specific tokens, the far-away
// upstash mention no longer drags it in.
func TestFromData_FP_FarVendorKey(t *testing.T) {
	// Pad with >64 bytes between the upstash marker and the foreign key.
	padding := strings.Repeat("# unrelated config comment line\n", 4) // ~128 bytes
	body := []byte("UPSTASH_REDIS_REST_URL=https://us1-x.upstash.io\n" +
		padding +
		"SENTRY_AUTH_TOKEN=" + dummy + "\n")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	for _, r := range res {
		if string(r.Raw) == dummy {
			t.Fatalf("foreign key far from upstash context should be suppressed, got %+v", r)
		}
	}
}

// FP #3: an all-decimal long run near an upstash mention is rejected by
// the character-diversity gate (no lower, no upper).
func TestFromData_FP_AllDecimalRun(t *testing.T) {
	dec := "12345678901234567890123456789012345678901234567890123456"
	body := []byte("upstash\nrequest_id=" + dec)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("all-decimal run should be suppressed, got %+v", res)
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "AbCdEfGh") {
		t.Fatalf("missing prefix: %q", r)
	}
}
