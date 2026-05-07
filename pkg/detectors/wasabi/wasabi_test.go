package wasabi

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	// Avoid "wasabi" substring in the key body so the no-keyword
	// negative test doesn't accidentally match the contextKeyword.
	dummyKey    = "ZYXWVUTSRQ1234567890"
	dummySecret = "abcdefghijABCDEFGHIJ0123456789klMNOPQRST"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Wasabi {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# wasabi\nWASABI_ACCESS_KEY=" + dummyKey + "\nWASABI_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("X=" + dummyKey + "\nY=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_AWSPrefixSkipped(t *testing.T) {
	body := []byte("wasabi AKIAIOSFODNN7EXAMPLE secret " + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for AKIA prefix, got %d", len(res))
	}
}

func TestFromData_OnlyKey(t *testing.T) {
	body := []byte("wasabi " + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without paired secret, got %d", len(res))
	}
}
