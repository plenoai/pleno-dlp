package git

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

// ErrRemoteEmpty reports that the remote repository has no commits.
var ErrRemoteEmpty = errors.New("git: remote repository is empty")

// RemoteAuth carries optional HTTP Basic credentials for CloneRemote.
type RemoteAuth struct {
	Username string
	Password string
}

// CloneRemote bare-clones rawURL (all branches and tags) into a fresh
// temporary directory and returns its path plus a cleanup func. The caller
// walks the clone with Source like any local repository.
//
// Credentials are sent only to HTTPS clone URLs (HTTP is accepted for
// loopback hosts so tests can use httptest). URLs that embed userinfo are
// rejected so tokens never land in argv, logs, or error strings; pass them
// through auth instead. Unauthenticated clones accept any URL go-git
// supports, including local paths.
func CloneRemote(ctx context.Context, rawURL string, auth RemoteAuth) (string, func(), error) {
	if strings.TrimSpace(rawURL) == "" {
		return "", nil, errors.New("git: clone URL is required")
	}
	if strings.ContainsAny(rawURL, "\r\n") {
		return "", nil, errors.New("git: clone URL must be a single line")
	}
	if u, err := url.Parse(rawURL); err == nil && u.User != nil {
		return "", nil, errors.New("git: clone URL must not embed credentials; pass a token instead")
	}
	opts := &gogit.CloneOptions{URL: rawURL, Tags: gogit.AllTags}
	if auth.Password != "" {
		if err := requireSecureCloneURL(rawURL); err != nil {
			return "", nil, err
		}
		user := auth.Username
		if user == "" {
			user = "x-access-token"
		}
		opts.Auth = &githttp.BasicAuth{Username: user, Password: auth.Password}
	}
	dir, err := os.MkdirTemp("", "pleno-remote-git-")
	if err != nil {
		return "", nil, fmt.Errorf("git: mktemp for clone: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if _, err := gogit.PlainCloneContext(ctx, dir, true, opts); err != nil {
		cleanup()
		if ctx.Err() != nil {
			return "", nil, ctx.Err()
		}
		if errors.Is(err, transport.ErrEmptyRemoteRepository) {
			return "", nil, ErrRemoteEmpty
		}
		msg := err.Error()
		if auth.Password != "" {
			msg = strings.ReplaceAll(msg, auth.Password, "[REDACTED]")
		}
		return "", nil, fmt.Errorf("git: clone %s: %s", redactURL(rawURL), msg)
	}
	return dir, cleanup, nil
}

func requireSecureCloneURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("git: authenticated clone requires an absolute HTTP(S) URL, got %q", redactURL(raw))
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("git: authenticated clone must use HTTPS (HTTP only for loopback): %q", redactURL(raw))
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid url>"
	}
	u.User = nil
	u.RawQuery = ""
	return u.String()
}
