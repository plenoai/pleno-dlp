package wiz

import (
	"context"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var dummy = strings.Repeat("a", 60) + "." + strings.Repeat("b", 80) + "." + strings.Repeat("c", 60)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Wiz {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# wiz_io\nWIZ_TOKEN=" + dummy)
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
	body := []byte("wiz.io " + dummy + "\nwiz.io " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestFromData_NoSegments(t *testing.T) {
	short := strings.Repeat("a", 60)
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("wiz_io "+short))
	if len(res) != 0 {
		t.Fatalf("expected 0 for non-JWT shape, got %d", len(res))
	}
}

func TestRedactShort(t *testing.T) {
	if got := redact("abc"); got != "abc" {
		t.Fatalf("redact passthrough mismatch: %s", got)
	}
}
