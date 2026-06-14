//go:build detector_unit

package confluence

import (
	"context"
	"strings"
	"testing"
)

// Realistic shape: ATATT3xFfGF0 prefix + ~160 chars of high-entropy base64url
// body. Dummy only — never a real token.
const dummy = "ATATT3xFfGF0aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_=AbCdEf456GhIjKlMnOpQrStUvWxYz9876543210zZyYxXwWvVuUtTsSrR=+/"

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

// FP regression: a MongoDB ObjectId (exactly 24 hex chars) in a config near a
// Confluence note. The old [A-Za-z0-9]{24} regex matched this; the
// prefix-anchored regex must reject it.
func TestFromData_MongoObjectId_Suppressed(t *testing.T) {
	body := []byte("# synced to confluence\nconfluence_doc_id=507f1f77bcf86cd799439011")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("MongoDB ObjectId should not match, got %d", len(res))
	}
}

// FP regression: a 24-char build/asset fingerprint beside a confluence comment.
func TestFromData_AssetHash_Suppressed(t *testing.T) {
	body := []byte("// synced to confluence  assetHash=a1b2c3d4e5f6A7B8C9D0E1F2")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("asset hash should not match, got %d", len(res))
	}
}

// FP regression: a 24-char base64-ish session id near the confluence keyword.
func TestFromData_SessionId_Suppressed(t *testing.T) {
	body := []byte("confluence session sid=Zm9vYmFyYmF6cXV4MTIzNDU2")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("session id should not match, got %d", len(res))
	}
}

// Cross-detector guard: a bitbucketcloud ATCTT token must not fire confluence.
func TestFromData_ATCTT_Skipped(t *testing.T) {
	atctt := "ATCTT3xFfGF0" + strings.Repeat("aB1cD2eF3g", 10)
	body := []byte("confluence near bitbucket token=" + atctt)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("ATCTT token belongs to bitbucketcloud, got %d", len(res))
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
