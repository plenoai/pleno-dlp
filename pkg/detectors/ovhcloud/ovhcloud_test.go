package ovhcloud

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyToken = "abcdefghijklmnopqrstuvwxyzABCDEF"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.OVHCloud {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("ovh_consumer_key=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("k=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without ovh keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("ovh=" + dummyToken + "\nconsumer_key=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	if got := redact(dummyToken); got != "abcdefgh..." {
		t.Fatalf("unexpected redact: %s", got)
	}
}
