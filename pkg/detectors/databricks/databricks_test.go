package databricks

import (
	"context"
	"strings"
	"testing"
)

const dummy = "dapi0123456789abcdef0123456789abcdef"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("DATABRICKS_TOKEN="+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_HostCapture(t *testing.T) {
	body := "host=acme.cloud.databricks.com\ntoken=" + dummy
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if got := res[0].ExtraData["host"]; got != "acme.cloud.databricks.com" {
		t.Fatalf("expected host capture, got %q", got)
	}
}

func TestFromData_Negative(t *testing.T) {
	// Bare 32-hex is rejected — no `dapi` prefix.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("md5=0123456789abcdef0123456789abcdef"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "dapi0123") {
		t.Fatalf("missing prefix: %q", r)
	}
}
