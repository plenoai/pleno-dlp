package agoraio

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const id1 = "0123456789abcdef0123456789abcdef"
const id2 = "fedcba9876543210fedcba9876543210"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.AgoraIO {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("AGORA_APP_ID=" + id1 + " AGORA_APP_CERT=" + id2)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1 pair")
	}
	found := false
	for _, r := range res {
		if string(r.RawV2) == id1+":"+id2 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected RawV2 with both halves")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED " + id1 + " " + id2)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}
