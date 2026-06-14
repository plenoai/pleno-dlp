//go:build detector_unit

package stytch

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyTest = "secret-test-abcdef1234567890ABCDEFghijklmnopqrst="
	dummyLive = "secret-live-abcdef1234567890ABCDEFghijklmnopqrst="
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Stytch {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# stytch\nSTYTCH_SECRET=" + dummyTest)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummyTest))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_LiveCritical(t *testing.T) {
	body := []byte("stytch " + dummyLive)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1")
	}
	if res[0].Severity != detectors.SeverityCritical {
		t.Fatalf("expected SeverityCritical for live, got %v", res[0].Severity)
	}
}

func TestFromData_TestNotCritical(t *testing.T) {
	body := []byte("stytch " + dummyTest)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1")
	}
	if res[0].Severity == detectors.SeverityCritical {
		t.Fatalf("expected not critical for test, got %v", res[0].Severity)
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("stytch " + dummyTest + "\nstytch " + dummyTest)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}
