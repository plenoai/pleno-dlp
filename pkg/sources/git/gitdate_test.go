package git

import (
	"testing"
	"time"
)

func TestParseGitISODate(t *testing.T) {
	cases := map[string]string{
		"2011-08-29T06:50:23+09:00":  "2011-08-28T21:50:23Z",
		"2011-08-29T06:50:23Z":       "2011-08-29T06:50:23Z",
		"2011-08-29T06:50:23+518:00": "2011-08-07T16:50:23Z",
		"2011-08-29T06:50:23-518:30": "2011-09-19T21:20:23Z",
	}
	for in, want := range cases {
		got, err := parseGitISODate(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if s := got.UTC().Format(time.RFC3339); s != want {
			t.Errorf("%s: got %s want %s", in, s, want)
		}
	}
	for _, bad := range []string{"", "2011-08-29", "2011-08-29T06:50:23", "2011-08-29T06:50:23*01:00", "2011-08-29T06:50:23+1:0"} {
		if _, err := parseGitISODate(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}
