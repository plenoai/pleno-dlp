package cloudflarer2

import (
	"context"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyID     = "0123456789abcdef0123456789abcdef"
	dummySecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.CloudflareR2 {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# r2_access_key\nR2_ACCESS_KEY_ID=" + dummyID + "\nR2_SECRET=" + dummySecret)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].RawV2) != dummySecret {
		t.Fatalf("RawV2 mismatch: %q", string(res[0].RawV2))
	}
	if res[0].Severity != detectors.SeverityCritical {
		t.Fatalf("expected SeverityCritical, got %v", res[0].Severity)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("X=" + dummyID + "\nY=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without R2 keyword, got %d", len(res))
	}
}

func TestFromData_MissingSecret(t *testing.T) {
	body := []byte("# r2_access_key id only\nR2_ACCESS_KEY_ID=" + dummyID)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without companion secret, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyID)
	if r == dummyID {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "01234567") {
		t.Fatalf("missing prefix: %q", r)
	}
}
