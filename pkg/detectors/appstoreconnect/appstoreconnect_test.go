package appstoreconnect

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyPEM = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgEvVU0cKEMq2BjMz/
B0gpQs5HaW28EYsNUJzrnTJrjE2gCgYIKoZIzj0DAQehRANCAATHrYa8B+5zXDg+
YxQbT9ZxJQB+u0Hf4O3KaJq3iN1q9p+Y3ahbWgYHbb7Bv5mTm5Bx6xC4mKr1JY8O
GnRy3uql
-----END PRIVATE KEY-----`

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.AppStoreConnect {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# app_store_connect\n" + dummyPEM)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(dummyPEM))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_DotP8(t *testing.T) {
	// .p8 is a strong signal — the file extension Apple uses for these keys.
	body := []byte("AuthKey_ABC123.p8 contents:\n" + dummyPEM)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoMatch(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("# app_store_connect\nno key here"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("app_store_connect\n" + dummyPEM + "\napp_store_connect\n" + dummyPEM)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}
