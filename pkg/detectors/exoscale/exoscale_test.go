//go:build detector_unit

package exoscale

import (
	"bytes"
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyKey    = "EXOabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP0123456789ABCD"
	dummySecret = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Exoscale {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("exoscale_key=" + dummyKey + " exoscale_secret=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if !bytes.Equal(res[0].Raw, []byte(dummyKey)) {
		t.Fatalf("raw mismatch")
	}
	if !bytes.Equal(res[0].RawV2, []byte(dummySecret)) {
		t.Fatalf("rawv2 mismatch")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("k=" + dummyKey + " s=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without exoscale keyword, got %d", len(res))
	}
}

func TestFromData_NoSecret(t *testing.T) {
	body := []byte("exoscale_key=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without paired secret, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("exoscale=" + dummyKey + " " + dummySecret + "\nexoscale=" + dummyKey + " " + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

// TestFromData_FalsePositivesSuppressed verifies that base64url-shaped
// blobs which are NOT Exoscale secrets are no longer paired as RawV2,
// even when co-located with an EXO-shaped access key and the keyword.
func TestFromData_FalsePositivesSuppressed(t *testing.T) {
	cases := []struct {
		name string
		blob string
	}{
		{
			// 48-char hex (sha1 digest doubled): passes {40,80} shape but
			// is pure hex and low entropy.
			name: "hex_digest",
			blob: "da39a3ee5e6b4b0d3255bfef95601890afd80709da39a3ee",
		},
		{
			// PEM/DER base64 body line, ASN.1 MII prefix.
			name: "pem_body",
			blob: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234",
		},
		{
			// JWT header segment, fixed eyJ marker.
			name: "jwt_segment",
			blob: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9eyJzdWIxxx",
		},
		{
			// All-zeros config nonce: passes shape, fails entropy floor.
			name: "low_entropy_nonce",
			blob: "0000000000000000000000000000000000000000000",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte("exoscale_key=" + dummyKey + " value=" + tc.blob)
			res, _ := Scanner{}.FromData(context.Background(), false, body)
			if len(res) != 0 {
				t.Fatalf("expected %s to be suppressed, got %d results (RawV2=%q)",
					tc.name, len(res), res[0].RawV2)
			}
		})
	}
}

// TestFromData_SecretMustBeNearKeyword ensures the secret half itself must
// be within secretVicinity of a context keyword; a real-shaped secret far
// from any keyword (only the key is near it) is not paired.
func TestFromData_SecretMustBeNearKeyword(t *testing.T) {
	// Place keyword+key together, then push a valid-shaped secret > 256
	// bytes away (still inside the 512 search radius).
	gap := bytes.Repeat([]byte("."), 400)
	body := append([]byte("exoscale_key="+dummyKey+" "), gap...)
	body = append(body, []byte(" "+dummySecret)...)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected secret far from keyword to be suppressed, got %d", len(res))
	}
}

// TestFromData_TruePositiveStillDetected guards against over-tightening:
// a realistic high-entropy base64url secret near the keyword is detected.
func TestFromData_TruePositiveStillDetected(t *testing.T) {
	body := []byte("# exoscale credentials\nEXOSCALE_API_KEY=" + dummyKey +
		"\nEXOSCALE_API_SECRET=" + dummySecret + "\n")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 true positive, got %d", len(res))
	}
	if !bytes.Equal(res[0].RawV2, []byte(dummySecret)) {
		t.Fatalf("rawv2 mismatch: %q", res[0].RawV2)
	}
}
