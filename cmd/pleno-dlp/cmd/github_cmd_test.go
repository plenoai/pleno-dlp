package cmd

import "testing"

func TestScanGitHubConfigAcceptsGitHubAppEnv(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GITHUB_APP_ID", "123")
	t.Setenv("GITHUB_APP_INSTALLATION_ID", "42")
	t.Setenv("GITHUB_APP_PRIVATE_KEY_FILE", "/tmp/app.pem")

	cfg, err := scanGitHubConfig(githubFlags{org: "acme", includeComments: true})
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
}

func TestScanGitHubConfigRejectsTokenAndGitHubApp(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_test")
	t.Setenv("GITHUB_APP_ID", "123")

	if _, err := scanGitHubConfig(githubFlags{org: "acme"}); err == nil {
		t.Fatal("expected ambiguous auth error")
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
