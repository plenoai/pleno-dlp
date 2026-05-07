package auth0

import (
	"context"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiaXNzIjoiYXV0aDAifQ.signature_part_long_enough"

func TestFromData_PositiveWithKeyword(t *testing.T) {
	body := []byte("AUTH0_TOKEN=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Severity != detectors.SeverityCritical {
		t.Fatalf("expected SeverityCritical, got %v", res[0].Severity)
	}
	if res[0].Verified {
		t.Fatal("Auth0 is unverified-by-design (audience unknown)")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("X=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword (generic JWT detector handles this), got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "eyJhbGciOiJI") {
		t.Fatalf("missing prefix: %q", r)
	}
}
