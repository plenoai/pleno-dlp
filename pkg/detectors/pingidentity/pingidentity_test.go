package pingidentity

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "abcdef01-2345-6789-abcd-ef0123456789"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.PingIdentity {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# pingidentity\nPING_ONE_SECRET=" + dummy)
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

func TestFromData_KeywordWordOnly(t *testing.T) {
	// "ping" alone (without identity/one) should not match even though it's the keyword
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("# ping latency\nX="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 for non-context ping, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("ping_identity " + dummy + "\nping_identity " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	if got := redact(dummy); got != dummy[:8]+"..." {
		t.Fatalf("redact mismatch: %s", got)
	}
}
