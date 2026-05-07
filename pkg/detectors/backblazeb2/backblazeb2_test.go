package backblazeb2

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyID  = "K003abcdef0123456789ghijk"
	dummyKey = "K003ABCDEF0123456789ghijklMNOPQRstuvwxyz"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.BackblazeB2 {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# b2_application_key\nB2_KEY_ID=" + dummyID + "\nB2_APP_KEY=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if string(res[0].Raw) != dummyID {
		t.Fatalf("Raw mismatch")
	}
	if string(res[0].RawV2) == "" {
		t.Fatal("RawV2 empty")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("X=" + dummyID + "\nY=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_OnlyID(t *testing.T) {
	body := []byte("b2_app id only " + dummyID)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without paired key, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("b2_ " + dummyID + "\nb2_ " + dummyKey + "\nb2_ " + dummyID)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}
