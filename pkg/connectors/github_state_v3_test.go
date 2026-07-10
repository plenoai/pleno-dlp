package connectors

import (
	"strings"
	"testing"
	"time"
)

func TestGitHubStateRejectsFutureVersion(t *testing.T) {
	state, err := loadGitHubIncrementalState(`{"version":4,"surfaces":{"repository-history":{"acme/r":{"mode":"history"}}}}`)
	if err == nil || state != nil || !strings.Contains(err.Error(), "newer than supported") {
		t.Fatalf("state=%#v err=%v", state, err)
	}
}

func TestGitHubStateV1MigrationPreservesRepositoryState(t *testing.T) {
	s, err := loadGitHubIncrementalState(`{"version":1,"repos":{"acme/old":{"mode":"history","ref_heads":{"main":"abc"}}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != 3 || s.Surfaces["repository-history"]["acme/old"].RefHeads["main"] != "abc" {
		t.Fatalf("state=%#v", s)
	}
}

func TestGitHubStateV2MigrationPreservesAllSurfaceNamespaces(t *testing.T) {
	s, err := loadGitHubIncrementalState(`{"version":2,"surfaces":{"repository-history":{"acme/r":{"mode":"history"}},"repository-wiki":{"acme/r":{"mode":"history"}},"gist-history":{"abc":{"mode":"history"}},"gist-comments":{"abc":{"issue_comments":{"1":{"updated_at":"x"}}}}}}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, surface := range []string{"repository-history", "repository-wiki", "gist-history", "gist-comments"} {
		if len(s.Surfaces[surface]) != 1 {
			t.Fatalf("lost %s: %#v", surface, s.Surfaces)
		}
	}
}

func TestGitHubStateV3RenameRestoresByStableID(t *testing.T) {
	cfg := Config{"org": "acme"}
	scope := githubScopeFingerprint(cfg)
	s := &githubIncrementalState{Version: 3, ScopeFingerprint: scope, Surfaces: map[string]map[string]githubRepoIncrementalState{"repository-history": {"acme/old": {StableID: "42", Mode: "history", RefHeads: map[string]string{"main": "abc"}}}}, Tombstones: map[string]githubStateTombstone{}}
	r := githubRepoRef{ID: 42, Name: "new"}
	r.Owner.Login = "acme"
	if _, err := prepareGitHubStateV3(s, []githubRepoRef{r}, cfg, time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.Surfaces["repository-history"]["acme/new"].RefHeads["main"] != "abc" {
		t.Fatalf("rename not restored: %#v", s.Surfaces)
	}
}

func TestGitHubStateV3PrunesOnlyAfterAgeAndCompleteRuns(t *testing.T) {
	cfg := Config{"org": "acme", "state_retention_days": "30", "state_retention_runs": "3"}
	now := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	s := &githubIncrementalState{Version: 3, ScopeFingerprint: githubScopeFingerprint(cfg), CompleteRuns: 2, Surfaces: map[string]map[string]githubRepoIncrementalState{"repository-history": {"acme/gone": {StableID: "9", Mode: "history", UnobservedSince: now.Add(-31 * 24 * time.Hour).Format(time.RFC3339), UnobservedRuns: 2}}}, Tombstones: map[string]githubStateTombstone{}}
	pruned, err := prepareGitHubStateV3(s, nil, cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 1 || len(s.Surfaces["repository-history"]) != 0 {
		t.Fatalf("pruned=%d state=%#v", pruned, s)
	}
}

func TestGitHubStateV3ScopeChangeDoesNotAgeState(t *testing.T) {
	s := &githubIncrementalState{Version: 3, ScopeFingerprint: "old", Surfaces: map[string]map[string]githubRepoIncrementalState{"repository-history": {"acme/hidden": {Mode: "history"}}}}
	if p, err := prepareGitHubStateV3(s, nil, Config{"org": "other"}, time.Now()); err != nil || p != 0 || s.Surfaces["repository-history"]["acme/hidden"].UnobservedRuns != 0 {
		t.Fatalf("p=%d err=%v state=%#v", p, err, s)
	}
}

func TestGitHubStateV3FilteredObservedRepositoryNeverAges(t *testing.T) {
	now := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	cfg := Config{"org": "acme", "exclude_repo_globs": "acme/private"}
	r := githubRepoRef{ID: 42, Name: "private"}
	r.Owner.Login = "acme"
	selected, _, err := githubFilterRepos(cfg, []githubRepoRef{r})
	if err != nil || len(selected) != 0 {
		t.Fatalf("selected=%#v err=%v", selected, err)
	}
	s := &githubIncrementalState{Version: 3, ScopeFingerprint: githubScopeFingerprint(cfg), Surfaces: map[string]map[string]githubRepoIncrementalState{"repository-history": {"acme/private": {StableID: "42", Mode: "history"}}}}
	if _, err := prepareGitHubStateV3(s, []githubRepoRef{r}, cfg, now); err != nil {
		t.Fatal(err)
	}
	got := s.Surfaces["repository-history"]["acme/private"]
	if got.UnobservedRuns != 0 || got.UnobservedSince != "" {
		t.Fatalf("observed filtered repository aged: %#v", got)
	}
}
