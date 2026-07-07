//go:build detector_unit

package railsmasterkey

import (
	"context"
	"testing"
)

func TestFromData_Match(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("7ac21fd94b6e0c831a5f2d9e7c4b81f0"))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "7ac21fd94b6e0c831a5f2d9e7c4b81f0" {
		t.Fatalf("got %q", res[0].Raw)
	}
}

func TestFromData_MatchWithTrailingNewline(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("7ac21fd94b6e0c831a5f2d9e7c4b81f0\n"))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
}

func TestFromData_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"all zero — degenerate", "00000000000000000000000000000000"},
		{"all f — degenerate", "ffffffffffffffffffffffffffffffff"},
		{"too short", "7ac21fd94b6e0c831a5f2d9e7c4b81"},
		{"too long", "7ac21fd94b6e0c831a5f2d9e7c4b81f0aa"},
		{"uppercase hex not matched", "7AC21FD94B6E0C831A5F2D9E7C4B81F0"},
		{"has trailing content — not the whole chunk", "7ac21fd94b6e0c831a5f2d9e7c4b81f0 extra"},
		{"a full ruby file, not a bare key", "class Foo\n  KEY = '7ac21fd94b6e0c831a5f2d9e7c4b81f0'\nend\n"},
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
