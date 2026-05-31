package modal

import (
	"context"
	"strings"
	"testing"
)

const dummyID = "ak-AbCdEf0123456789AbCd"
const dummySecret = "as-ZyXwVu9876543210ZyXw"

func TestFromData_Pair(t *testing.T) {
	body := []byte("MODAL_TOKEN_ID=" + dummyID + "\nMODAL_TOKEN_SECRET=" + dummySecret)
	res, err := Scanner{}.FromData(context.Background(), false, body)
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
		t.Fatalf("rawv2 mismatch: %q", res[0].RawV2)
	}
}

func TestFromData_OnlyID(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("MODAL_TOKEN_ID="+dummyID))
	if len(res) != 0 {
		t.Fatalf("expected 0 without secret, got %d", len(res))
	}
}

// TestFromData_SuppressedFalsePositives asserts the entropy/charset gate
// rejects identifier/label concatenations and placeholder docs samples that
// satisfy the `{20,}` length regex but are not real Modal credentials.
func TestFromData_SuppressedFalsePositives(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			// all-lowercase dictionary-word concatenations (no digit, no upper)
			name: "lowercase_word_concat",
			body: "ak-administrationkeyspace paired-with as-applicationservicelayer",
		},
		{
			// all-digit / placeholder bodies: no uppercase, low entropy
			name: "placeholder_docs_sample",
			body: "MODAL_TOKEN_ID=ak-1234567890abcdefghij\nMODAL_TOKEN_SECRET=as-0000000000aaaaaaaaaa",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := Scanner{}.FromData(context.Background(), false, []byte(c.body))
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if len(res) != 0 {
				t.Fatalf("expected 0 (suppressed), got %d: %+v", len(res), res)
			}
		})
	}
}

// TestFromData_TruePositiveStillDetected asserts a realistic high-entropy
// mixed-case-with-digits pair still passes the hardened gate.
func TestFromData_TruePositiveStillDetected(t *testing.T) {
	body := []byte("MODAL_TOKEN_ID=" + dummyID + "\nMODAL_TOKEN_SECRET=" + dummySecret)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 (still detected), got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyID)
	if r == dummyID {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "ak-AbCdE") {
		t.Fatalf("missing prefix: %q", r)
	}
}
