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
