package tencentcloud

import (
	"context"
	"strings"
	"testing"
)

const dummyID = "AKIDabcdefghijklmnopqrstuvwxyz0123"
const dummySecret = "abcdefghijklmnopqrstuvwxyz012345"

func TestFromData_Pair(t *testing.T) {
	body := "tencent_secret_id=" + dummyID + "\ntencent_secret_key=" + dummySecret + "\n"
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyID {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != dummySecret {
		t.Fatalf("rawV2 mismatch: %q", res[0].RawV2)
	}
	if res[0].Severity != 5 {
		t.Fatalf("expected critical for paired creds, got %d", res[0].Severity)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("random "+dummyID+" word"))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyID)
	if r == dummyID {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "AKIDabcd") {
		t.Fatalf("missing prefix: %q", r)
	}
}
