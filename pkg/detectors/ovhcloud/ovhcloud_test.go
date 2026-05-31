package ovhcloud

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummyToken is a mixed-case 32-char alnum string: clears the lowercase-hex
// exclusion and the entropy floor, so it stands in for a real OVH key.
const dummyToken = "abcdefghijklmnopqrstuvwxyzABCDEF"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.OVHCloud {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("ovh_consumer_key=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

// True positive: ovhcloud keyword within the tight vicinity radius.
func TestFromData_OVHCloudKeyword(t *testing.T) {
	body := []byte("# ovhcloud creds\napplication_secret = " + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 true positive, got %d", len(res))
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("k=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without ovh keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("ovh_application_key=" + dummyToken + "\novh_consumer_key=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

// FP suppressed: a generic OAuth1 consumer_key field plus an unrelated MD5
// digest. "consumer_key" is only a coarse prefilter, never a proximity
// match, and the 32-char run is pure lowercase hex.
func TestFromData_FP_GenericConsumerKeyPlusMD5(t *testing.T) {
	body := []byte("consumer_key = twitterapp\n# build checksum 9f86d081884c7d659a2feaa0c55ad015\n")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected MD5 + generic consumer_key suppressed, got %d", len(res))
	}
}

// FP suppressed: 'ovh' mentioned in a comment near a hyphen-stripped UUID.
// The token is lowercase hex, and bare 'ovh' is no longer a proximity kw.
func TestFromData_FP_OVHCommentPlusUUID(t *testing.T) {
	body := []byte("// ovh migration note\nrequest_id: 550e8400e29b41d4a716446655440000\n")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected UUID near 'ovh' comment suppressed, got %d", len(res))
	}
}

// FP suppressed: ovhcloud lockfile line with a truncated MD5 sha — even with
// the literal 'ovhcloud' present, the lowercase-hex token is rejected.
func TestFromData_FP_LockfileMD5(t *testing.T) {
	body := []byte("ovhcloud-sdk integrity sha (truncated): d41d8cd98f00b204e9800998ecf8427e\n")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected lockfile MD5 suppressed, got %d", len(res))
	}
}

// FP suppressed: low-entropy structured 32-char value near an OVH keyword.
func TestFromData_FP_LowEntropy(t *testing.T) {
	body := []byte("ovh_application_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected low-entropy token suppressed, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	if got := redact(dummyToken); got != "abcdefgh..." {
		t.Fatalf("unexpected redact: %s", got)
	}
}
