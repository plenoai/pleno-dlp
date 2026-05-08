package smee

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Smee {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("WEBHOOK_PROXY_URL=https://smee.io/AbCdEf1234567890")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_NoMatch(t *testing.T) {
	body := []byte("WEBHOOK_PROXY_URL=https://example.com/abc")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("URL=https://smee.io/AbCdEf1234567890\nURL=https://smee.io/AbCdEf1234567890")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 dedup, got %d", len(res))
	}
}
