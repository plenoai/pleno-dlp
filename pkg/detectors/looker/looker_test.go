package looker

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Realistic base62 shapes: not pure-hex, not pure-decimal, entropy > 3.5.
const dummyClientID = "Zk9Wn2Qr7Lp4Xs1Td6Vb"
const dummyClientSecret = "Gh3Mn8Bq2Wz5Yx7Ld0Pk"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Looker {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

// TestFromData_Found: a true positive — field-anchored client_id /
// client_secret pair stays detected.
func TestFromData_Found(t *testing.T) {
	body := []byte("looker_client_id=" + dummyClientID + " looker_client_secret=" + dummyClientSecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
	if string(res[0].RawV2) != dummyClientID+":"+dummyClientSecret {
		t.Fatalf("RawV2 mismatch: %s", res[0].RawV2)
	}
	if string(res[0].Raw) != dummyClientID {
		t.Fatalf("Raw mismatch: %s", res[0].Raw)
	}
}

// TestFromData_FoundAPI3: api3-prefixed field names also match.
func TestFromData_FoundAPI3(t *testing.T) {
	body := []byte(`looker_sdk: { api3_client_id: "` + dummyClientID + `", api3_client_secret: "` + dummyClientSecret + `" }`)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED=" + dummyClientID + " " + dummyClientSecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// --- False positives now SUPPRESSED by the hardening ---

// FP1: a docs page mentioning Looker plus two truncated git SHAs / build
// hashes. Two 20-char tokens within 256 bytes of "looker", but they are
// not anchored to client_id/client_secret field names. SUPPRESSED.
func TestFromData_FP_BuildHashesNearLooker(t *testing.T) {
	body := []byte("looker dashboard build a1b2c3d4e5f60718293a ref 0f1e2d3c4b5a69788796")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected build-hash FP suppressed, got %d", len(res))
	}
}

// FP2: pure-hex UUID-without-dashes fragments attached to the field names.
// Anchored, but rejected by the pure-hex negative class. SUPPRESSED.
func TestFromData_FP_PureHexFields(t *testing.T) {
	body := []byte("looker client_id=550e8400e29b41d4a716 client_secret=446655440000abcdef12")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected pure-hex FP suppressed, got %d", len(res))
	}
}

// FP3: pure-decimal numeric IDs attached to the field names. Rejected by
// the pure-decimal negative class. SUPPRESSED.
func TestFromData_FP_PureDecimalFields(t *testing.T) {
	body := []byte("looker client_id=12345678901234567890 client_secret=09876543210987654321")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected pure-decimal FP suppressed, got %d", len(res))
	}
}

// FP4: low-entropy padded / repeated runs attached to the field names.
// Rejected by the entropy gate. SUPPRESSED.
func TestFromData_FP_LowEntropyFields(t *testing.T) {
	body := []byte("looker client_id=aaaaaaaaaaaaaaaaaaaa client_secret=bbbbbbbbbbbbbbbbbbbb")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected low-entropy FP suppressed, got %d", len(res))
	}
}

// FP5: a README listing Looker as a BI integration next to two unrelated
// 20-char API keys, with no client_id/client_secret anchoring. SUPPRESSED.
func TestFromData_FP_UnanchoredKeysNearLooker(t *testing.T) {
	body := []byte("Supported integrations: Looker. OTHER_KEY=" + dummyClientID + " OTHER_TOKEN=" + dummyClientSecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected unanchored-keys FP suppressed, got %d", len(res))
	}
}
