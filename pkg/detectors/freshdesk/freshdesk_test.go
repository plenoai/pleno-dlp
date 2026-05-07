package freshdesk

import (
	"context"
	"testing"
)

const dummy = "fd0123456789abcdefABCD"

func TestFromData_Positive(t *testing.T) {
	body := "freshdesk_api_key=" + dummy
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
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
	body := "host=acme.freshdesk.com\nfreshdesk_token=" + dummy
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if got := res[0].ExtraData["host"]; got != "acme.freshdesk.com" {
		t.Fatalf("expected host capture, got %q", got)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("random_token="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}
