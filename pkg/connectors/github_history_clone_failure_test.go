package connectors

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestIsGitHubCloneFailure(t *testing.T) {
	disabled := classifyGitHubCloneError(errors.New("exit status 128"), "remote: Repository 'acme/x' is disabled.\nfatal: The requested URL returned error: 403")
	timeout := &githubCloneError{Kind: githubCloneTimeout, Err: context.DeadlineExceeded, Detail: "exceeded 30m0s"}
	for name, err := range map[string]error{
		"classified": fmt.Errorf("github: clone acme/x: %w", disabled),
		"timeout":    fmt.Errorf("github: clone acme/big: %w", timeout),
	} {
		if !IsGitHubCloneFailure(err) {
			t.Fatalf("%s: IsGitHubCloneFailure(%v) = false, want true", name, err)
		}
	}
	for name, err := range map[string]error{
		"nil":      nil,
		"walk":     fmt.Errorf("github: repository walk acme/x exceeded 2h0m0s: %w", context.DeadlineExceeded),
		"canceled": context.Canceled,
	} {
		if IsGitHubCloneFailure(err) {
			t.Fatalf("%s: IsGitHubCloneFailure(%v) = true, want false", name, err)
		}
	}
}

func TestGitHubRepoCloneTimeout(t *testing.T) {
	for raw, want := range map[string]time.Duration{"": 0, "0": 0, "0s": 0, "30m": 30 * time.Minute} {
		got, err := githubRepoCloneTimeout(Config{"repo_clone_timeout": raw})
		if err != nil || got != want {
			t.Fatalf("githubRepoCloneTimeout(%q) = (%s, %v), want %s", raw, got, err, want)
		}
	}
	for _, raw := range []string{"-1s", "soon"} {
		if _, err := githubRepoCloneTimeout(Config{"repo_clone_timeout": raw}); err == nil {
			t.Fatalf("githubRepoCloneTimeout(%q) accepted invalid duration", raw)
		}
	}
}
