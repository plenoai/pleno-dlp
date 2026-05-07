package clickhousecloud

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyID     = "AbCdEf0123456789AbCdEf0123456789"
	dummySecret = "aaaabbbbccccddddeeeeffff0000111122223333aaaabbbb"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.ClickHouseCloud {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# clickhouse_cloud\nID=" + dummyID + "\nSECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if string(res[0].RawV2) == "" {
		t.Fatal("expected RawV2 paired secret")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("ID=" + dummyID + "\nSECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyID)
	if r == dummyID {
		t.Fatal("redact didn't redact")
	}
}

func TestFromData_NoSecret(t *testing.T) {
	body := []byte("# clickhouse_cloud\nID=" + dummyID)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without paired secret, got %d", len(res))
	}
}
