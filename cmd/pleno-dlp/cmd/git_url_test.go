package cmd

import (
	"context"
	"strings"
	"testing"
)

func TestResolveGitScanRepoFlagRules(t *testing.T) {
	cases := map[string]struct {
		opts gitFlags
		want string
	}{
		"repo and url":      {opts: gitFlags{repo: "x", gitURL: "https://example.com/r.git"}, want: "mutually exclusive"},
		"token without url": {opts: gitFlags{repo: "x", gitToken: "t"}, want: "require --git-url"},
		"userinfo url":      {opts: gitFlags{gitURL: "https://u:p@example.com/r.git"}, want: "must not embed credentials"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, cleanup, err := resolveGitScanRepo(context.Background(), tc.opts)
			cleanup()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	got, cleanup, err := resolveGitScanRepo(context.Background(), gitFlags{repo: "local"})
	defer cleanup()
	if err != nil || got != "local" {
		t.Fatalf("local repo = %q, %v", got, err)
	}
}
