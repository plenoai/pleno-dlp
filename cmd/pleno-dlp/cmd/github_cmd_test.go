package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

func TestScanGitHubHelpDocumentsSurfacesDefaultsAndCosts(t *testing.T) {
	resetCommandFlags(t)
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"scan", "github", "--help"})
	if err := Root.Execute(); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{"full commit history", "pull-request refs", "zero REST calls", "--include-comments", "--include-issues", "--include-pull-requests", "--include-wikis", "--gist", "--include-authenticated-gists", "--include-gist-comments", "--repo-concurrency", "default 1", "--repo-walk-timeout", "--include-commit-metadata", "--skip-merge-commits", "--trufflehog-compatible", "--include-git-archives", "--include-git-binaries", "hard cap 2 GiB", "--include-forks", "default true", "--include-archived"} {
		if !strings.Contains(got, want) {
			t.Errorf("help missing %q:\n%s", want, got)
		}
	}
}

func TestScanGitHubConfigAcceptsTwoGiBArchiveCeiling(t *testing.T) {
	cfg, err := scanGitHubConfig(githubFlags{
		repo:                    "example/project",
		token:                   "token",
		gitArtifactMaxBytes:     2 << 30,
		archiveMaxExpandedBytes: 2 << 30,
	})
	if err != nil {
		t.Fatalf("2 GiB ceiling rejected: %v", err)
	}
	if cfg["git_artifact_max_bytes"] != "2147483648" || cfg["archive_max_expanded_bytes"] != "2147483648" {
		t.Fatalf("2 GiB limits were not preserved: %#v", cfg)
	}
}

func TestScanGitHubConfigAcceptsGitHubAppEnv(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GITHUB_APP_ID", "123")
	t.Setenv("GITHUB_APP_INSTALLATION_ID", "42")
	t.Setenv("GITHUB_APP_PRIVATE_KEY_FILE", "/tmp/app.pem")

	cfg, err := scanGitHubConfig(githubFlags{org: "acme", includeComments: true, includeCommitMetadata: true, skipMergeCommits: true, trufflehogCompatible: true})
	if err != nil {
		t.Fatalf("scanGitHubConfig: %v", err)
	}
	if cfg["token"] != "" {
		t.Fatalf("token must be empty for GitHub App auth")
	}
	if cfg["app_id"] != "123" || cfg["app_installation_id"] != "42" || cfg["app_private_key_file"] != "/tmp/app.pem" {
		t.Fatalf("GitHub App config not populated: %#v", cfg)
	}
	if cfg["include_comments"] != "true" {
		t.Fatalf("include_comments = %q, want true", cfg["include_comments"])
	}
	if cfg["include_commit_metadata"] != "true" {
		t.Fatalf("include_commit_metadata = %q, want true", cfg["include_commit_metadata"])
	}
	if cfg["skip_merge_commits"] != "true" {
		t.Fatalf("skip_merge_commits = %q, want true", cfg["skip_merge_commits"])
	}
	if cfg["trufflehog_compatible"] != "true" {
		t.Fatalf("trufflehog_compatible = %q, want true", cfg["trufflehog_compatible"])
	}
}

func TestGitHubScannerFingerprintConfigTracksSurfaceWithoutCredentials(t *testing.T) {
	resetCommandFlags(t)
	base := connectors.Config{
		"org":                     "acme",
		"trufflehog_compatible":   "false",
		"token":                   "token-one",
		"app_id":                  "app-one",
		"app_installation_id":     "installation-one",
		"app_private_key":         "private-key-one",
		"app_private_key_file":    "/credentials/one.pem",
		"include_git_archives":    "false",
		"include_commit_metadata": "false",
		"repo_concurrency":        "1",
		"repo_walk_timeout":       "30m",
		"state_retention_days":    "30",
		"state_retention_runs":    "3",
	}
	encoded, err := githubScannerFingerprintConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"token", "app_id", "app_installation_id", "app_private_key", "app_private_key_file"} {
		if _, ok := decoded[key]; ok {
			t.Fatalf("credential key %q retained in scanner fingerprint config", key)
		}
	}

	rotated := connectors.Config{}
	for key, value := range base {
		rotated[key] = value
	}
	rotated["token"] = "token-two"
	rotated["app_private_key"] = "private-key-two"
	rotatedEncoded, err := githubScannerFingerprintConfig(rotated)
	if err != nil {
		t.Fatal(err)
	}
	baseFP, err := scannerFingerprint("github", encoded)
	if err != nil {
		t.Fatal(err)
	}
	rotatedFP, err := scannerFingerprint("github", rotatedEncoded)
	if err != nil {
		t.Fatal(err)
	}
	if baseFP != rotatedFP {
		t.Fatal("credential rotation changed scanner fingerprint")
	}

	retuned := connectors.Config{}
	for key, value := range base {
		retuned[key] = value
	}
	retuned["repo_concurrency"] = "8"
	retuned["repo_walk_timeout"] = "1h"
	retuned["state_retention_days"] = "90"
	retuned["state_retention_runs"] = "10"
	retunedEncoded, err := githubScannerFingerprintConfig(retuned)
	if err != nil {
		t.Fatal(err)
	}
	retunedFP, err := scannerFingerprint("github", retunedEncoded)
	if err != nil {
		t.Fatal(err)
	}
	if baseFP != retunedFP {
		t.Fatal("execution-control change changed scanner fingerprint")
	}

	changed := connectors.Config{}
	for key, value := range base {
		changed[key] = value
	}
	changed["trufflehog_compatible"] = "true"
	changedEncoded, err := githubScannerFingerprintConfig(changed)
	if err != nil {
		t.Fatal(err)
	}
	changedFP, err := scannerFingerprint("github", changedEncoded)
	if err != nil {
		t.Fatal(err)
	}
	if baseFP == changedFP {
		t.Fatal("trufflehog compatibility change did not change scanner fingerprint")
	}
}

func TestScanGitHubConfigRejectsTokenAndGitHubApp(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_test")
	t.Setenv("GITHUB_APP_ID", "123")

	if _, err := scanGitHubConfig(githubFlags{org: "acme"}); err == nil {
		t.Fatal("expected ambiguous auth error")
	}
}

func TestScanGitHubConfigRepoConcurrency(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_test")
	cfg, err := scanGitHubConfig(githubFlags{org: "acme", repoConcurrency: 4})
	if err != nil {
		t.Fatalf("scanGitHubConfig: %v", err)
	}
	if got := cfg["repo_concurrency"]; got != "4" {
		t.Fatalf("repo_concurrency = %q, want 4", got)
	}
	if _, err := scanGitHubConfig(githubFlags{org: "acme", repoConcurrency: 33}); err == nil {
		t.Fatal("expected repo concurrency range error")
	}
}

func TestScanGitHubConfigRepoWalkTimeout(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_test")
	cfg, err := scanGitHubConfig(githubFlags{org: "acme", repoWalkTimeout: 45 * time.Minute})
	if err != nil {
		t.Fatalf("scanGitHubConfig: %v", err)
	}
	if got := cfg["repo_walk_timeout"]; got != "45m0s" {
		t.Fatalf("repo_walk_timeout = %q, want 45m0s", got)
	}
	if _, err := scanGitHubConfig(githubFlags{org: "acme", repoWalkTimeout: -time.Second}); err == nil {
		t.Fatal("expected negative repo walk timeout error")
	}
}

func TestScanGitHubConfigEnumerationControls(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_test")
	cfg, err := scanGitHubConfig(githubFlags{
		org: "acme", includeRepoGlobs: []string{"acme/*", "alice/tool"},
		excludeRepoGlobs: []string{"*/legacy"}, includeForks: true,
		includeArchived: true, expandMembers: true, commentsTimeframeDays: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg["include_repo_globs"] != "acme/*\nalice/tool" || cfg["exclude_repo_globs"] != "*/legacy" ||
		cfg["include_forks"] != "true" || cfg["include_archived"] != "true" || cfg["expand_members"] != "true" ||
		cfg["comments_timeframe_days"] != "30" {
		t.Fatalf("enumeration config = %#v", cfg)
	}
	if _, err := scanGitHubConfig(githubFlags{org: "acme", commentsTimeframeDays: -1}); err == nil {
		t.Fatal("expected negative comment timeframe error")
	}
}

func TestScanGitHubConfigCollaborationSurfaces(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_test")
	cfg, err := scanGitHubConfig(githubFlags{org: "acme", includeIssues: true, includePullRequests: true, collabTimeframeDays: 14})
	if err != nil {
		t.Fatal(err)
	}
	if cfg["include_issues"] != "true" || cfg["include_pull_requests"] != "true" || cfg["include_comments"] != "false" || cfg["collab_timeframe_days"] != "14" {
		t.Fatalf("collaboration config = %#v", cfg)
	}
	if _, err := scanGitHubConfig(githubFlags{org: "acme", collabTimeframeDays: -1}); err == nil {
		t.Fatal("expected negative collaboration timeframe error")
	}
}

func TestScanGitHubConfigWikiSurface(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_test")
	cfg, err := scanGitHubConfig(githubFlags{org: "acme", includeWikis: true})
	if err != nil || cfg["include_wikis"] != "true" {
		t.Fatalf("wiki config=%v err=%v", cfg, err)
	}
}

func TestScanGitHubConfigGistScopes(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_test")
	cfg, err := scanGitHubConfig(githubFlags{gistURLs: []string{"https://gist.github.com/alice/abc"}, includeAuthenticatedGists: true, includeGistComments: true})
	if err != nil || cfg["gist_urls"] != "https://gist.github.com/alice/abc" || cfg["include_authenticated_gists"] != "true" || cfg["include_gist_comments"] != "true" {
		t.Fatalf("cfg=%v err=%v", cfg, err)
	}
}

func TestVerifyGitHubConfigAcceptsGitHubAppEnv(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GITHUB_APP_ID", "123")
	t.Setenv("GITHUB_APP_INSTALLATION_ID", "42")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", "pem")

	cfg, token, err := verifyGitHubConfig(githubFlags{})
	if err != nil {
		t.Fatalf("verifyGitHubConfig: %v", err)
	}
	if token != "" {
		t.Fatalf("token = %q, want empty for GitHub App auth", token)
	}
	if cfg["app_id"] != "123" || cfg["app_installation_id"] != "42" || cfg["app_private_key"] != "pem" {
		t.Fatalf("GitHub App verify config not populated: %#v", cfg)
	}
}
