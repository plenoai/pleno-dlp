package azuread

import (
	"context"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummySecret = "AbC8Q~aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ab"
const dummyAppID = "01234567-89ab-cdef-0123-456789abcdef"

func TestFromData_Positive_PairsAppID(t *testing.T) {
	body := []byte("AZURE_CLIENT_ID=" + dummyAppID + "\nAZURE_CLIENT_SECRET=" + dummySecret)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummySecret {
		t.Fatalf("Raw mismatch: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != dummyAppID {
		t.Fatalf("RawV2 mismatch: %q", res[0].RawV2)
	}
	if res[0].Severity != detectors.SeverityCritical {
		t.Fatalf("expected SeverityCritical, got %v", res[0].Severity)
	}
	if res[0].Verified {
		t.Fatal("AzureAD is unverified-by-design (tenant unknown)")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("X=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_Negative_NoTilde(t *testing.T) {
	body := []byte("AZURE_CLIENT_SECRET=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without tilde, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummySecret)
	if r == dummySecret {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "AbC8Q~") {
		t.Fatalf("missing prefix: %q", r)
	}
}
