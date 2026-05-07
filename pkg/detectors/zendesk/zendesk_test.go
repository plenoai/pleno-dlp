package zendesk

import (
	"context"
	"testing"
)

const dummyTok = "abcdefghij0123456789ABCDEFGHIJabcdefghij"
const dummyEmail = "ops@example.com"

func TestFromData_Pair(t *testing.T) {
	body := "zendesk_email=" + dummyEmail + "\nzendesk_token=" + dummyTok
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyTok {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != dummyEmail {
		t.Fatalf("rawV2 mismatch: %q", res[0].RawV2)
	}
}

func TestFromData_HostCapture(t *testing.T) {
	body := "host=acme.zendesk.com\nzendesk_token=" + dummyTok
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if got := res[0].ExtraData["host"]; got != "acme.zendesk.com" {
		t.Fatalf("expected host capture, got %q", got)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("token="+dummyTok))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}
