package exoscale

import (
	"bytes"
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyKey    = "EXOabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP0123456789ABCD"
	dummySecret = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Exoscale {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("exoscale_key=" + dummyKey + " exoscale_secret=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if !bytes.Equal(res[0].Raw, []byte(dummyKey)) {
		t.Fatalf("raw mismatch")
	}
	if !bytes.Equal(res[0].RawV2, []byte(dummySecret)) {
		t.Fatalf("rawv2 mismatch")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("k=" + dummyKey + " s=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without exoscale keyword, got %d", len(res))
	}
}

func TestFromData_NoSecret(t *testing.T) {
	body := []byte("exoscale_key=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without paired secret, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("exoscale=" + dummyKey + " " + dummySecret + "\nexoscale=" + dummyKey + " " + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}
