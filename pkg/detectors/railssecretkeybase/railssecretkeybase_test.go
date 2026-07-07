//go:build detector_unit

package railssecretkeybase

import (
	"context"
	"testing"
)

const syntheticKeyBase = "e1f2a3b4c5d6e7f809182736455463728190a1b2c3d4e5f60718293a4b5c6d7e8f9012a3b4c5d6e7f8091827364554637281a2b3c4d5e6f708192a3b4c5d67"

func TestFromData_Match(t *testing.T) {
	data := []byte("development:\n  secret_key_base: " + syntheticKeyBase + "\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != syntheticKeyBase {
		t.Fatalf("got %q", res[0].Raw)
	}
}

func TestFromData_MultipleEnvironments(t *testing.T) {
	data := []byte(
		"development:\n  secret_key_base: " + syntheticKeyBase + "\n" +
			"test:\n  secret_key_base: " + syntheticKeyBase[:1] + syntheticKeyBase[2:] + "z\n",
	)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 2 {
		t.Fatalf("expected 2, got %d: %+v", len(res), res)
	}
}

func TestFromData_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"ERB env lookup, not a literal", `secret_key_base: <%= ENV["SECRET_KEY_BASE"] %>`},
		{"too short to be a real Rails key", "secret_key_base: abc123"},
		{"placeholder word", "secret_key_base: changeme"},
		{"empty value", "secret_key_base: "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(tc.data))
			if len(res) != 0 {
				t.Fatalf("expected 0, got %d findings for %q: %+v", len(res), tc.data, res)
			}
		})
	}
}
