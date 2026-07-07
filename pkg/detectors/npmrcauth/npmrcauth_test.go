//go:build detector_unit

package npmrcauth

import (
	"context"
	"testing"
)

func TestFromData_AuthToken(t *testing.T) {
	data := []byte("registry=\"https://registry.npmjs.org/\"\n" +
		"//registry.npmjs.org/:_authToken=unit-test-fixture-authtoken-not-a-real-value-0000\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "unit-test-fixture-authtoken-not-a-real-value-0000" {
		t.Fatalf("got %q", res[0].Raw)
	}
	if res[0].ExtraData["key"] != "_authToken" {
		t.Fatalf("key = %q", res[0].ExtraData["key"])
	}
}

func TestFromData_AuthBase64NonPlaceholder(t *testing.T) {
	// base64("svc_deploy:R3alNpmR3gistryPassZz8k")
	data := []byte("_auth = c3ZjX2RlcGxveTpSM2FsTnBtUjNnaXN0cnlQYXNzWno4aw==\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "c3ZjX2RlcGxveTpSM2FsTnBtUjNnaXN0cnlQYXNzWno4aw==" {
		t.Fatalf("got %q", res[0].Raw)
	}
}

func TestFromData_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		// leaky-repo's own .npmrc fixture: `_auth` decodes to the
		// documentation placeholder pair "admin:admin" — see package
		// doc comment for the decode-and-check rationale.
		{"auth decodes to admin:admin placeholder", "_auth = YWRtaW46YWRtaW4=\n"},
		{"password directly a placeholder", "_password = changeme\n"},
		{"too short", "_authToken=ab\n"},
		{"unrelated key", "email=dummy@example.com\n"},
		{"invalid base64 kept as-is not suppressed", "_auth = not-base64-!!\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(tc.data))
			switch tc.name {
			case "invalid base64 kept as-is not suppressed":
				if len(res) != 1 {
					t.Fatalf("expected 1 (raw blob kept), got %d: %+v", len(res), res)
				}
			default:
				if len(res) != 0 {
					t.Fatalf("expected 0, got %d findings for %q: %+v", len(res), tc.data, res)
				}
			}
		})
	}
}

func TestFromData_Dedup(t *testing.T) {
	data := []byte("_authToken=unit-test-fixture-authtoken-not-a-real-value-0000\n" +
		"_authToken=unit-test-fixture-authtoken-not-a-real-value-0000\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1 deduped, got %d", len(res))
	}
}
