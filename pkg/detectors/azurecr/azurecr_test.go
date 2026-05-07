package azurecr

import (
	"context"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var dummyToken = "eyJ" + strings.Repeat("a", 30) + "." + strings.Repeat("b", 80) + "." + strings.Repeat("c", 40)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.AzureContainerRegistry {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_AzurecrHost(t *testing.T) {
	body := []byte("docker login myregistry.azurecr.io -p " + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_AcrTokenKeyword(t *testing.T) {
	body := []byte("acr_refresh_token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("azurecr=" + dummyToken + "\nazurecr=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestFromData_NotJWTShaped(t *testing.T) {
	body := []byte("azurecr=" + strings.Repeat("a", 50))
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for non-JWT shape, got %d", len(res))
	}
}
