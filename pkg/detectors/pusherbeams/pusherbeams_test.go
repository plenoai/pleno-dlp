package pusherbeams

import (
	"context"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyToken = "abcdef0123456789abcdef0123456789"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.PusherBeams {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("pusher_beams secret=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without pusher_beams keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("pusher_beams=" + dummyToken + "\nbeams_secret=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestFromData_TooShort(t *testing.T) {
	body := []byte("pusher_beams=abcdef0123")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for too-short token, got %d", len(res))
	}
}

// FP fixture 1: an md5 of an empty file co-located with the bare word "beams"
// inside the old 256-byte radius. Bare "beams" is no longer a keyword and the
// vicinity is now 48 bytes, so this must be suppressed.
func TestFromData_FP_FarBeamsMD5(t *testing.T) {
	body := []byte("asset_integrity_beams banner\n" +
		strings.Repeat("# padding line that keeps the hash far from any keyword\n", 4) +
		"checksum = d41d8cd98f00b204e9800998ecf8427e")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for far md5 near bare 'beams', got %d", len(res))
	}
}

// FP fixture 2: an ETag/cache-header dump. Even with a beams-ish word nearby,
// the "etag" negative keyword in the same window must suppress the match.
func TestFromData_FP_ETagHeader(t *testing.T) {
	body := []byte("etag: 5d41402abc4b2a76b9719d911017c592 # beams_secret banner cache")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for etag header context, got %d", len(res))
	}
}

// FP fixture 3: an all-zero placeholder hex right next to the keyword. The
// entropy floor rejects it.
func TestFromData_FP_LowEntropyPlaceholder(t *testing.T) {
	body := []byte("beams_secret=00000000000000000000000000000000")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy placeholder, got %d", len(res))
	}
}

// TP fixture: a real-shaped secret assignment-adjacent to the keyword with no
// hash negative word. Must still be detected.
func TestFromData_TP_StillDetected(t *testing.T) {
	body := []byte("beams_secret = " + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 true positive, got %d", len(res))
	}
}
