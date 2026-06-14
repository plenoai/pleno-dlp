//go:build detector_unit

package atlassian

import (
	"context"
	"strings"
	"testing"
)

// Realistic shape: fixed ATATT3 prefix + long high-entropy base64url body.
// Not a real token. Real tokens run ~190+ chars; this is shortened but keeps
// the prefix and entropy profile the detector now anchors on.
const dummy = "ATATT3xFfGF0aZ9kQ2mNpR7sT4vW8xY1bC3dE6fG0hJ5kL2mN9pQ4rS7tU0vWxYzAbCdEfGhIjKlMn"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("ATLASSIAN_API_TOKEN="+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Verified {
		t.Fatal("Atlassian tokens are unverified-by-design (need email); got Verified=true")
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

// True positive: token referenced near an *.atlassian.net host (stronger
// contextual anchor) is still detected.
func TestFromData_Positive_AtlassianNetHost(t *testing.T) {
	body := "curl https://acme.atlassian.net/rest/api/3/myself -u me@acme.com:" + dummy
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_NoKeyword_DoesNotMatch(t *testing.T) {
	// Valid-shaped token without any atlassian keyword nearby → must skip.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("token="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	// Wrong shape near keyword: no ATATT3 prefix.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("atlassian short123"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// FP suppressed: a 24-char hex build hash near "atlassian" no longer matches,
// because the regex now requires the ATATT3 prefix.
func TestFromData_FP_HexBuildHash(t *testing.T) {
	body := "atlassian-connect plugin build a1b2c3d4e5f6a1b2c3d4e5f6"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("hex build hash must be suppressed; got %d", len(res))
	}
}

// FP suppressed: an arbitrary 24-char identifier near the keyword. No ATATT3
// prefix → no match.
func TestFromData_FP_ArbitraryIdentifier(t *testing.T) {
	body := "// atlassian integration\nbuildId = AbCdEfGhIjKlMnOpQrStUvWx"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("arbitrary identifier must be suppressed; got %d", len(res))
	}
}

// FP suppressed: a low-entropy body that happens to carry the ATATT3 prefix
// (sequential/repeated run) is dropped by the entropy gate.
func TestFromData_FP_LowEntropyBody(t *testing.T) {
	body := "atlassian token=ATATT3aaaaaaaaaaaaaaaaaaaaaaaa"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("low-entropy body must be suppressed; got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "ATATT3") {
		t.Fatalf("missing prefix: %q", r)
	}
}
