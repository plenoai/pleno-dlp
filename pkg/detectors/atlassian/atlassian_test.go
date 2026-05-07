package atlassian

import (
	"context"
	"strings"
	"testing"
)

const dummy = "ATATT3xFfGF0AbCdEfGhIjKl"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("ATLASSIAN_API_TOKEN="+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Verified {
		t.Fatal("Atlassian tokens are unverified-by-design (need email); got Verified=true")
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_NoKeyword_DoesNotMatch(t *testing.T) {
	// 24-alnum without "atlassian" keyword nearby → must skip.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("token="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	// Wrong length near keyword.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("atlassian short123"))
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
