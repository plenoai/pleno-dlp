package aliyun

import (
	"context"
	"strings"
	"testing"
)

const dummyID = "LTAIabcdef0123456789"
const dummySecret = "abcdefghijklmnopqrstuvwxyz0123"

func TestFromData_Pair(t *testing.T) {
	body := "aliyun_access_key_id=" + dummyID + "\naliyun_access_key_secret=" + dummySecret + "\n"
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(res))
	}
	if string(res[0].Raw) != dummyID {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != dummySecret {
		t.Fatalf("rawV2 mismatch: %q", res[0].RawV2)
	}
	if res[0].Severity != 5 { // SeverityCritical
		t.Fatalf("expected critical severity for paired creds, got %d", res[0].Severity)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	// LTAI alone with no aliyun/alibaba context keyword should be ignored.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("random log line "+dummyID+" appears here"))
	if len(res) != 0 {
		t.Fatalf("expected 0 hits without context, got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("aliyun nothing here"))
	if len(res) != 0 {
		t.Fatalf("expected 0 hits, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyID)
	if r == dummyID {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "LTAIabcd") {
		t.Fatalf("missing prefix: %q", r)
	}
}
