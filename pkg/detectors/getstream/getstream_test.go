package getstream

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyKey = "abcdef0123456789"
const dummySecret = "ZYXWVU9876543210zyxwvu"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.GetStream {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("GETSTREAM_KEY=" + dummyKey + "\nGETSTREAM_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if len(res) >= 1 && string(res[0].RawV2) == "" {
		t.Fatal("expected RawV2 to carry secret")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("KEY=" + dummyKey + "\nSECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without getstream keyword, got %d", len(res))
	}
}

// TestFromData_TruePositives covers the realistic high-variety credential
// shapes that MUST survive the entropy / class-variety hardening.
func TestFromData_TruePositives(t *testing.T) {
	cases := map[string]string{
		"stream_api_key marker": "stream_api_key = \"" + dummyKey + "\"\nstream_api_secret = \"" + dummySecret + "\"",
		"getstream secret":      "getstream_key=" + dummyKey + " getstream_secret=" + dummySecret,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
			if len(res) == 0 {
				t.Fatalf("expected >=1 detection, got 0")
			}
		})
	}
}

// TestFromData_FalsePositivesSuppressed asserts the previously-noisy shapes
// (bare URL/identifier anchors pairing low-entropy / single-class / Git-SHA
// tokens) now return zero results.
func TestFromData_FalsePositivesSuppressed(t *testing.T) {
	cases := map[string]string{
		// bare getstream.io URL near two all-lowercase config tokens
		"docs url + lowercase config": "// docs: https://getstream.io/chat/docs\n" +
			"const region = \"useast1prodcluster\"\n" +
			"const bucket = \"streamingdataarchive\"",
		// streamio identifier + two low-entropy alnum runs
		"streamio config low entropy": "streamio.Config{ Endpoint: \"abcdefghijklmnop\", Namespace: \"production0000000\" }",
		// two 40-char hex Git SHAs near stream.io
		"git shas near stream.io": "// stream.io migration\n" +
			"commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa parent bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		// repeated-char + dictionary token pair near streamio keyword
		"streamio table dictionary": "streamio_table rows: id=000000000000 token=helloworldfoobar",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
			if len(res) != 0 {
				t.Fatalf("expected 0 (false positive suppressed), got %d: %+v", len(res), res)
			}
		})
	}
}
