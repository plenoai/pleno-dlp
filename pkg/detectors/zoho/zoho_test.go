//go:build detector_unit

package zoho

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "1000.abc123ABC456def789ghi012jkl345MN.xyz123ABC456def789ghi012jkl345MN"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Zoho {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# zoho\nZOHO_REFRESH=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_BadShape(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("zoho 1000.abc.short"))
	if len(res) != 0 {
		t.Fatalf("expected 0 for short segments, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("zoho " + dummy + "\nzoho " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

// Hardening: all-lowercase-hex segments are build digests, not Zoho
// refresh tokens (which are mixed-case base62). Suppressed.
func TestFromData_SuppressAllHexDigest(t *testing.T) {
	body := []byte("# zoho integration\nbuild_hash=1000.a1b2c3d4e5f60718293a4b5c6d7e8f90.deadbeefcafef00dba5eba11c0ffee99")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for all-hex digest, got %d", len(res))
	}
}

// Hardening: low-entropy padded numeric placeholder passes {32,} but is
// not a real token. Suppressed (all-decimal + entropy floor).
func TestFromData_SuppressLowEntropyPadding(t *testing.T) {
	body := []byte("// zoho notes\nartifact=1000.00000000000000000000000000000000.11111111111111111111111111111111")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy padding, got %d", len(res))
	}
}

// Hardening: a timestamp+log fragment co-located within the old 256B
// window but >64B from the zoho keyword, with an all-decimal first
// segment. Suppressed by both the decimal exclusion and the tighter
// vicinity. We assert suppression here via the decimal segment.
func TestFromData_SuppressDecimalLogFragment(t *testing.T) {
	body := []byte("zoho_log: 1000.1700000000000000000000000000000.9988776655443322110099887766554433")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for decimal log fragment, got %d", len(res))
	}
}

// Hardening: a zoho keyword far (>64B) from the token must not match,
// even though it is in the same chunk.
func TestFromData_SuppressKeywordTooFar(t *testing.T) {
	pad := make([]byte, 120)
	for i := range pad {
		pad[i] = ' '
	}
	body := []byte("zoho" + string(pad) + "X=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 when keyword >64B away, got %d", len(res))
	}
}

// True positive still detected: mixed-case base62 segments adjacent to a
// zoho keyword.
func TestFromData_StillDetectsRealShape(t *testing.T) {
	body := []byte("ZOHO_REFRESH=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 for real mixed-case token, got %d", len(res))
	}
}
