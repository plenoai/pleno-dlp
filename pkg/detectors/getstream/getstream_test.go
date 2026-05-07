package getstream

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyKey = "abcdef0123456789"
const dummySecret = "ZYXWVU9876543210zyxwvu"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.GetStream {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("GETSTREAM_KEY=" + dummyKey + "\nGETSTREAM_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if len(res) >= 1 && string(res[0].RawV2) == "" {
		t.Fatal("expected RawV2 to carry secret")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("KEY=" + dummyKey + "\nSECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without getstream keyword, got %d", len(res))
	}
}
