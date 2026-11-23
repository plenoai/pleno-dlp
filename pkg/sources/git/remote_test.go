package git

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
)

func TestCloneRemoteWalksFullHistoryOfClone(t *testing.T) {
	src, hashes := buildRepo(t, []commitSpec{
		{msg: "one", files: map[string]string{"a.txt": "first secret\n"}},
		{msg: "two", files: map[string]string{"a.txt": "second secret\n"}},
	})
	dir, cleanup, err := CloneRemote(context.Background(), src, RemoteAuth{})
	if err != nil {
		t.Fatalf("CloneRemote: %v", err)
	}
	s := &Source{}
	mustInit(t, s, Config{Repo: dir, AllBranches: true})
	chunks, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	seen := map[string]bool{}
	for _, c := range chunks {
		seen[c.SourceMetadata.Git.Commit] = true
	}
	for _, h := range hashes {
		if !seen[h] {
			t.Errorf("commit %s not walked from clone", h)
		}
	}
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("cleanup left %s behind: %v", dir, err)
	}
}

func TestCloneRemoteRejectsUnsafeInputs(t *testing.T) {
	cases := map[string]struct {
		url  string
		auth RemoteAuth
		want string
	}{
		"empty":            {url: "", want: "required"},
		"multiline":        {url: "https://example.com/a.git\nx", want: "single line"},
		"userinfo":         {url: "https://user:tok@example.com/a.git", want: "must not embed credentials"},
		"token over http":  {url: "http://example.com/a.git", auth: RemoteAuth{Password: "tok"}, want: "must use HTTPS"},
		"token over local": {url: "/tmp/repo", auth: RemoteAuth{Password: "tok"}, want: "absolute HTTP(S) URL"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := CloneRemote(context.Background(), tc.url, tc.auth)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CloneRemote(%q) err = %v, want %q", tc.url, err, tc.want)
			}
			if tc.auth.Password != "" && strings.Contains(err.Error(), tc.auth.Password) {
				t.Fatalf("error leaks token: %v", err)
			}
		})
	}
}

func TestCloneRemoteEmptyRepository(t *testing.T) {
	dir := t.TempDir()
	if _, err := gogit.PlainInit(dir, true); err != nil {
		t.Fatal(err)
	}
	_, _, err := CloneRemote(context.Background(), dir, RemoteAuth{})
	if !errors.Is(err, ErrRemoteEmpty) {
		t.Fatalf("err = %v, want ErrRemoteEmpty", err)
	}
}
