package awssession

import (
	"context"
	"strings"
	"testing"
)

const dummyID = "ASIAQWERTYUIOPASDFGH"
const dummySecret = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
const dummySession = "FwoGZXIvYXdzECAaDF1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij"

func TestFromData_TripleNearKeyword(t *testing.T) {
	body := []byte("AWS_ACCESS_KEY_ID=" + dummyID + "\n" +
		"AWS_SECRET_ACCESS_KEY=" + dummySecret + "\n" +
		"AWS_SESSION_TOKEN=" + dummySession + "\n")
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyID {
		t.Fatalf("Raw mismatch: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != dummySecret {
		t.Fatalf("RawV2 mismatch: %q", res[0].RawV2)
	}
	if res[0].Verified {
		t.Fatal("AWSSession is unverified-by-design (region unknown); got Verified=true")
	}
	if res[0].ExtraData["access_key_id"] != dummyID {
		t.Fatalf("extra access_key_id mismatch")
	}
}

func TestFromData_NoSessionContext(t *testing.T) {
	// Bare ASIA without any session_token co-occurrence and no keyword
	// nearby — must not fire. ASIA shows up in IAM policy fixtures.
	body := []byte("Resource: arn:aws:iam::000000000000:role/foo " + dummyID)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyID)
	if r == dummyID {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "ASIAQWER") {
		t.Fatalf("missing prefix: %q", r)
	}
}
