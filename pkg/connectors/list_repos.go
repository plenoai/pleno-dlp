package connectors

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Repository is one entry of a --list-only enumeration.
type Repository struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// ListRepositories enumerates the repositories the named connector would
// scan for cfg, without fetching any content. It returns an error for
// connectors that do not enumerate repositories.
func ListRepositories(ctx context.Context, name string, cfg Config) ([]Repository, error) {
	var (
		repos []Repository
		err   error
	)
	switch name {
	case "github":
		repos, err = listGitHubRepositories(ctx, cfg)
	case "gitlab":
		repos, err = listGitLabRepositories(ctx, cfg)
	default:
		return nil, fmt.Errorf("--list-only is not supported for %q (supported: github, gitlab)", name)
	}
	if err != nil {
		return nil, err
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].Name < repos[j].Name })
	return repos, nil
}

func listGitHubRepositories(ctx context.Context, cfg Config) ([]Repository, error) {
	auth, err := newGitHubAuthProvider(cfg)
	if err != nil {
		return nil, err
	}
	org, repo := cfg["org"], cfg["repo"]
	if org == "" && repo == "" && len(splitList(cfg["user"])) == 0 {
		return nil, errors.New("github: --list-only requires --org, --repo, or --user")
	}
	if repo != "" {
		if parts := strings.SplitN(repo, "/", 2); len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("github: repo must be in owner/name form, got %q", repo)
		}
	}
	apiBase := cfg.Get("api_base", githubDefaultAPIBase)
	u, err := url.Parse(apiBase)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("github: invalid api_base %q", apiBase)
	}
	if err := validateGitHubAuthenticatedTransport(apiBase, auth != nil); err != nil {
		return nil, err
	}
	selected, _, _, err := githubEnumerateRepos(ctx, newGitHubClient(apiBase, auth), cfg, org, repo)
	if err != nil {
		return nil, err
	}
	web := githubWebBase(u)
	out := make([]Repository, 0, len(selected))
	for _, r := range selected {
		full := r.Owner.Login + "/" + r.Name
		out = append(out, Repository{Name: full, URL: web + "/" + full + ".git"})
	}
	return out, nil
}

// githubWebBase maps an API base to the clone host: api.github.com →
// https://github.com, GHE https://host/api/v3 → https://host.
func githubWebBase(api *url.URL) string {
	if strings.EqualFold(api.Host, "api.github.com") {
		return "https://github.com"
	}
	return api.Scheme + "://" + api.Host
}

func listGitLabRepositories(ctx context.Context, cfg Config) ([]Repository, error) {
	token := cfg["token"]
	if token == "" {
		return nil, errors.New("gitlab: token is required (set --token or GITLAB_TOKEN)")
	}
	group, project, user := cfg["group"], cfg["project"], cfg["user"]
	if countNonEmpty(group, project, user) != 1 {
		return nil, errors.New("gitlab: --list-only requires exactly one of group, project, or user")
	}
	apiBase := cfg.Get("api_base", gitlabDefaultAPIBase)
	if err := requireSecureEndpoint("gitlab", apiBase); err != nil {
		return nil, err
	}
	projects, err := gitlabListProjects(ctx, newGitLabClient(apiBase, token), group, project, user)
	if err != nil {
		return nil, err
	}
	out := make([]Repository, 0, len(projects))
	for _, p := range projects {
		out = append(out, Repository{Name: p.PathWithNS, URL: p.HTTPURLToRepo})
	}
	return out, nil
}
