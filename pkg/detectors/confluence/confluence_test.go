package confluence

import (
	"context"
	"strings"
	"testing"
)

const dummy = "ATATT3xFfGF0abcdEfgh1234"

func TestFromData_Positive(t *testing.T) {
	body := []byte("CONFLUENCE_API_TOKEN=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Verified {
		t.Fatal("confluence is unverified-by-design")
	}
}

func TestFromData_NoKeyword_DoesNotMatch(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("token="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("confluence=short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "ATATT3") {
		t.Fatalf("missing prefix: %q", r)
	}
}
