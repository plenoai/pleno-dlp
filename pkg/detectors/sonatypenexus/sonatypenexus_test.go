//go:build detector_unit

package sonatypenexus

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "NXRT-abcdef0123456789-ABCDEFghijklmnop"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.SonatypeNexus {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# nexus\nNEXUS_TOKEN=" + dummy)
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
	body := []byte("nexus " + dummy + "\nnexus " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestFromData_BadShape(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("nexus ABCD-foo"))
	if len(res) != 0 {
		t.Fatalf("expected 0 (must start with NXRT-), got %d", len(res))
	}
}
