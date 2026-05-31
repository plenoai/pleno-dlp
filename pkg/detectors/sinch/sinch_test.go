package sinch

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// realKey is a realistic high-entropy random UUID-shaped API key.
const realKey = "9f3c7a1e-4b2d-46e8-bd91-7c0a5e83f612"

// seqDummy is the sequential placeholder that the doc/SDK examples use. It
// matches the shape but is now suppressed by the entropy / lookalike gates.
const seqDummy = "12345678-1234-1234-1234-1234567890ab"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Sinch {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

// TestFromData_Positive: a real high-entropy key assigned to SINCH_API_KEY is
// still detected after hardening.
func TestFromData_Positive(t *testing.T) {
	body := []byte("# sinch\nSINCH_API_KEY=" + realKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

// TestFromData_PositiveColonAssignment: `sinch:` style assignment context.
func TestFromData_PositiveColonAssignment(t *testing.T) {
	body := []byte("sinch_token: " + realKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+realKey))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("sinch_key=" + realKey + "\nsinch_key=" + realKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestFromData_BadShape(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("sinch_key=1234567812341234"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// --- Hardening: false positives now SUPPRESSED ---

// FP1: a request/trace correlation id sharing a wide window with the bare
// brand word `sinch` (no assignment context) must NOT surface — proximity to
// an assignment keyword is now required.
func TestFromData_FP_TraceIDNearBrandWord(t *testing.T) {
	body := []byte("// using the sinch SDK provider for delivery\n" +
		"X-Request-Id: f47ac10b-58cc-4372-a567-0e02b2c3d479")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (trace id near bare brand word), got %d", len(res))
	}
}

// FP2: the sequential doc/SDK example GUID under a `sinch` comment is now
// suppressed by the entropy + sequential-lookalike gates even though it sits
// next to an assignment keyword.
func TestFromData_FP_SequentialPlaceholder(t *testing.T) {
	body := []byte("# sinch example config\nSINCH_API_KEY=" + seqDummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (sequential placeholder), got %d", len(res))
	}
}

// FP3: the all-zero placeholder project_id sample is suppressed.
func TestFromData_FP_AllZeroPlaceholder(t *testing.T) {
	body := []byte("sinch_key=00000000-0000-0000-0000-000000000000")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (all-zero placeholder), got %d", len(res))
	}
}

// FP4: a real, high-entropy UUID that only co-occurs with the bare brand word
// within the old 256-byte window (but >64 bytes from any assignment keyword)
// is no longer reported.
func TestFromData_FP_HighEntropyFarFromKeyword(t *testing.T) {
	pad := make([]byte, 120)
	for i := range pad {
		pad[i] = ' '
	}
	body := append([]byte("sinch_api_key reference appears here"), pad...)
	body = append(body, []byte(realKey)...)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (real key beyond proximity radius), got %d", len(res))
	}
}
