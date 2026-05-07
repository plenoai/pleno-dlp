package upstashredis

import (
	"context"
	"strings"
	"testing"
)

const dummy = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUv"

func TestFromData_Positive(t *testing.T) {
	body := []byte("# upstash\nUPSTASH_REDIS_REST_TOKEN=" + dummy + "\nUPSTASH_REDIS_REST_URL=https://us1-test-12345.upstash.io")
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) == 0 {
		t.Fatalf("expected at least 1, got %d", len(res))
	}
	var found bool
	for _, r := range res {
		if string(r.Raw) == dummy {
			found = true
			if got := r.ExtraData["host"]; got != "us1-test-12345.upstash.io" {
				t.Fatalf("expected host capture, got %q", got)
			}
		}
	}
	if !found {
		t.Fatalf("expected dummy token in results: %+v", res)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "AbCdEfGh") {
		t.Fatalf("missing prefix: %q", r)
	}
}
