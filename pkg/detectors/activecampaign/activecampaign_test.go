package activecampaign

import (
	"context"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcd"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.ActiveCampaign {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# activecampaign\nAC_API_KEY=" + dummy)
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

func TestFromData_Dedup(t *testing.T) {
	body := []byte("activecampaign " + dummy + "\nactivecampaign " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestFromData_TooShort(t *testing.T) {
	short := strings.Repeat("a", 40)
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("activecampaign "+short))
	if len(res) != 0 {
		t.Fatalf("expected 0 for too-short, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	if got := redact(dummy); !strings.HasSuffix(got, "...") {
		t.Fatalf("redact suffix mismatch: %s", got)
	}
}
