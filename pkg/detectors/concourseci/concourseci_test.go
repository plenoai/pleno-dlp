//go:build detector_unit

package concourseci

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// realToken is a high-entropy, mixed-case, URL-safe base64 run with an
// embedded `-`/`_` and a digit+letter mix — the shape of an actual `fly
// login` bearer token. Not a real credential.
const realToken = "xZ4kQ9m-B2nF7pR1wL6tY_3vH8jD0sA5cE"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.ConcourseCI {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

// TestFromData_Positive: a realistic fly token near a concourse keyword is
// still detected after hardening.
func TestFromData_Positive(t *testing.T) {
	body := []byte("# concourse\nFLY_TOKEN=" + realToken)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != realToken {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+realToken))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("concourse=" + realToken + "\nconcourse=" + realToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

// TestFromData_SuppressedFalsePositives locks the hardening gates: each of
// these 28-64 char runs sits within 256 bytes of a concourse keyword and
// would have matched the old `\b([A-Za-z0-9_-]{28,64})\b` regex, but is now
// suppressed because it is a lookalike, not an opaque fly bearer token.
func TestFromData_SuppressedFalsePositives(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			// 40-char git commit SHA in a README mentioning concourse.
			name: "commit_sha_hex",
			body: "concourse pipeline at 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
		},
		{
			// dash-free UUID / md5-shaped run beside a concourse_token comment.
			name: "dashfree_uuid_hex",
			body: "# concourse_token env\n0a1b2c3d4e5f60718293a4b5c6d7e8f9",
		},
		{
			// the old committed doc dummy: all-hex placeholder.
			name: "hex_doc_dummy",
			body: "# concourse\nFLY_TOKEN=AbCdEf0123456789AbCdEf01234567",
		},
		{
			// low-entropy all-alpha path segment near concourse_url=.
			name: "low_entropy_alpha",
			body: "concourse_url=https://ci/teamsmainpipelinesxxxxxxxxxxxx",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Scanner{}.FromData(context.Background(), false, []byte(tc.body))
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if len(res) != 0 {
				t.Fatalf("expected 0 (suppressed), got %d: %+v", len(res), res)
			}
		})
	}
}
