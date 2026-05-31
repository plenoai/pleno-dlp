package spinnaker

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// tpToken is a realistic-shaped opaque Spinnaker bearer credential: 52-char
// base62, mixed case, high entropy (~5.2 bits/char), not pure-hex.
const tpToken = "aZ8kQ2mX7pL3nV9wR4tY6uB1cD5fG0hJ8kM2nP4qS6tU8vW0xZ2a"

// tpJWT is a structurally valid 3-segment JWT (header decodes to JSON with alg).
const tpJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiJzcGlubmFrZXItc3ZjIiwiaXNzIjoiZ2F0ZSJ9.c2lnbmF0dXJlX2J5dGVzX2hlcmU"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Spinnaker {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func count(t *testing.T, body string) int {
	t.Helper()
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("FromData error: %v", err)
	}
	return len(res)
}

// --- True positives: still detected after hardening ---

func TestFromData_TruePositive_Base62(t *testing.T) {
	if n := count(t, "SPINNAKER_TOKEN="+tpToken); n != 1 {
		t.Fatalf("expected base62 TP detected, got %d", n)
	}
}

func TestFromData_TruePositive_JWT(t *testing.T) {
	if n := count(t, "spinnaker_token: "+tpJWT); n != 1 {
		t.Fatalf("expected JWT TP detected, got %d", n)
	}
}

// --- False positives now suppressed by hardening ---

// 40-hex git SHA-1 near a gate.spinnaker anchor — pure-hex, rejected.
func TestFromData_FP_GitSHA1(t *testing.T) {
	body := "# pin gate.spinnaker to commit da39a3ee5e6b4b0d3255bfef95601890afd80709"
	if n := count(t, body); n != 0 {
		t.Fatalf("expected git SHA-1 suppressed, got %d", n)
	}
}

// 64-hex sha256 image digest near a spinnaker.io URL reference. Both the
// pure-hex gate and the dropped URL anchor suppress it.
func TestFromData_FP_Sha256Digest(t *testing.T) {
	body := "spinnaker.io/clouddriver@sha256:" +
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if n := count(t, body); n != 0 {
		t.Fatalf("expected sha256 digest suppressed, got %d", n)
	}
}

// Low-entropy structured identifier in assignment context — was the prior
// test's "dummy"; entropy gate (and pure-hex gate) now drop it.
func TestFromData_FP_LowEntropyIdentifier(t *testing.T) {
	body := "SPINNAKER_DIGEST=AbCdEf0123456789AbCdEf0123456789AbCdEf01AbCdEf01"
	if n := count(t, body); n != 0 {
		t.Fatalf("expected low-entropy identifier suppressed, got %d", n)
	}
}

// base64url config blob beginning eyJ near a spinnaker: YAML key — not a
// 3-segment JWT, rejected by the structural JWT gate.
func TestFromData_FP_NonJWTBlob(t *testing.T) {
	body := "spinnaker: eyJhbGciOiJpbnRlcm5hbCIsImNvbmZpZyI6dHJ1ZX0"
	if n := count(t, body); n != 0 {
		t.Fatalf("expected non-JWT eyJ blob suppressed, got %d", n)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	if n := count(t, "X="+tpToken); n != 0 {
		t.Fatalf("expected 0 without keyword, got %d", n)
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := "spinnaker=" + tpToken + "\nspinnaker=" + tpToken
	if n := count(t, body); n != 1 {
		t.Fatalf("expected dedup to 1, got %d", n)
	}
}

func TestRedact(t *testing.T) {
	if redact(tpToken) == tpToken {
		t.Fatal("redact didn't redact")
	}
}
