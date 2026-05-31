package segment

import (
	"context"
	"strings"
	"testing"
)

const dummy = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("SEGMENT_WRITE_KEY="+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Verified {
		t.Fatal("Segment write keys are unverified-by-design (would mint events); got Verified=true")
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_NoKeyword_DoesNotMatch(t *testing.T) {
	// 32-alnum without "segment" → must skip.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("token="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("segment short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_LowEntropyLookalikes_Suppressed asserts that 32-char strings
// which sit next to a Segment anchor but are clearly not random write keys
// (zeroed/repeated placeholders, MD5 hex, UUID-without-dashes) are dropped by
// the entropy floor / pure-hex exclusion rather than surfaced as findings.
func TestFromData_LowEntropyLookalikes_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{
			name: "zeroed placeholder config value",
			data: "segment_write_key=00000000000000000000000000000000",
		},
		{
			name: "md5 hex near anchor",
			data: "# segment.com migration note: md5sum d41d8cd98f00b204e9800998ecf8427e",
		},
		{
			name: "uuid without dashes near anchor",
			data: "segmentio user uuid 123e4567e89b12d3a456426614174000",
		},
		{
			name: "repeated-char 32 run",
			data: "segment.com cache key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Scanner{}.FromData(context.Background(), false, []byte(tc.data))
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if len(res) != 0 {
				t.Fatalf("expected 0 findings (suppressed lookalike), got %d: %+v", len(res), res)
			}
		})
	}
}

// TestFromData_HighEntropyStillDetected guards against the entropy floor being
// set so high it suppresses real keys: a random base62 write key next to a
// Segment anchor must still surface.
func TestFromData_HighEntropyStillDetected(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("segment.com write key "+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 (true positive still detected), got %d", len(res))
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "AbCdEf") {
		t.Fatalf("missing prefix: %q", r)
	}
}
