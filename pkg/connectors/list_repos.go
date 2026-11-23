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
	case "bitbucket":
		repos, err = listBitbucketRepositories(ctx, cfg)
	case "azure-devops":
		repos, err = listAzureDevOpsRepositories(ctx, cfg)
	case "huggingface":
		repos, err = listHuggingFaceRepositories(ctx, cfg)
	default:
		p, ok := giteaProviderByName(name)
		if !ok {
			return nil, fmt.Errorf("--list-only is not supported for %q (supported: %s)", name, strings.Join(ListOnlyConnectors(), ", "))
		}
		repos, err = listGiteaRepository(ctx, p, cfg)
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

// ListOnlyConnectors names every connector that supports --list-only.
func ListOnlyConnectors() []string {
	out := []string{"azure-devops", "bitbucket", "github", "gitlab", "huggingface"}
	for _, p := range giteaProviders {
		out = append(out, p.name)
	}
	sort.Strings(out)
	return out
}

func giteaProviderByName(name string) (giteaProvider, bool) {
	for _, p := range giteaProviders {
		if p.name == name {
			return p, true
		}
	}
	return giteaProvider{}, false
}

func listBitbucketRepositories(ctx context.Context, cfg Config) ([]Repository, error) {
	token, appPassword, username := cfg["token"], cfg["app_password"], cfg["username"]
	if token == "" && appPassword == "" {
		return nil, errors.New("bitbucket: token or app_password is required")
	}
	if token != "" && appPassword != "" {
		return nil, errors.New("bitbucket: token and app_password are mutually exclusive")
	}
	if appPassword != "" && username == "" {
		return nil, errors.New("bitbucket: username is required when using app_password auth")
	}
	workspace, repo := cfg["workspace"], cfg["repo"]
	if workspace == "" && repo == "" {
		return nil, errors.New("bitbucket: workspace or repo must be set")
	}
	apiBase := cfg.Get("api_base", bitbucketDefaultAPIBase)
	if err := requireSecureEndpoint("bitbucket", apiBase); err != nil {
		return nil, err
	}
	refs, err := bitbucketListRepos(ctx, newBitbucketClient(apiBase, username, appPassword, token), workspace, repo)
	if err != nil {
		return nil, err
	}
	out := make([]Repository, 0, len(refs))
	for i := range refs {
		out = append(out, Repository{Name: refs[i].FullName, URL: refs[i].httpsCloneURL()})
	}
	return out, nil
}

func listAzureDevOpsRepositories(ctx context.Context, cfg Config) ([]Repository, error) {
	cli, err := newAzureDevOpsClient(cfg, cfg["token"])
	if err != nil {
		return nil, err
	}
	refs, err := cli.listRepos(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Repository, 0, len(refs))
	for _, r := range refs {
		if r.IsDisabled {
			continue
		}
		out = append(out, Repository{Name: r.Project.Name + "/" + r.Name, URL: r.cloneURL()})
	}
	return out, nil
}

// listHuggingFaceRepositories lists git-backed repos (models, datasets,
// spaces). Buckets are object stores, not repositories, and are skipped.
func listHuggingFaceRepositories(ctx context.Context, cfg Config) ([]Repository, error) {
	owners := append(splitList(cfg["org"]), splitList(cfg["user"])...)
	repo := cfg["repo"]
	if len(owners) == 0 && repo == "" {
		return nil, errors.New("huggingface: --list-only requires org, user, or repo")
	}
	if len(owners) > 0 && repo != "" {
		return nil, errors.New("huggingface: org/user and repo are mutually exclusive")
	}
	apiBase := cfg.Get("api_base", hfDefaultAPIBase)
	if err := requireSecureEndpoint("huggingface", apiBase); err != nil {
		return nil, err
	}
	refs, err := hfListRepos(ctx, newHFClient(apiBase, cfg["token"]), owners, repo, parseRepoTypes(cfg.Get("repo_types", hfDefaultRepoTypes)))
	if err != nil {
		return nil, err
	}
	out := make([]Repository, 0, len(refs))
	for _, r := range refs {
		name := r.ID
		if r.Type != "" && r.Type != "model" {
			name = r.Type + "s/" + r.ID
		}
		out = append(out, Repository{Name: name, URL: hfBuildCloneURL(cfg, r)})
	}
	return out, nil
}

// listGiteaRepository confirms the single --repo scope Gitea-family scans
// accept exists and is readable, and returns it.
func listGiteaRepository(ctx context.Context, p giteaProvider, cfg Config) ([]Repository, error) {
	token := cfg["token"]
	if token == "" {
		return nil, fmt.Errorf("%s: token is required", p.name)
	}
	owner, name, ok := splitOwnerRepo(cfg["repo"])
	if !ok {
		return nil, fmt.Errorf("%s: repo must be in owner/name form, got %q", p.name, cfg["repo"])
	}
	apiBase := cfg.Get("api_base", p.apiBase)
	if apiBase == "" {
		return nil, fmt.Errorf("%s: --api-base is required", p.name)
	}
	if err := requireSecureEndpoint(p.name, apiBase); err != nil {
		return nil, err
	}
	var meta struct {
		FullName string `json:"full_name"`
	}
	if _, err := newGiteaClient(apiBase, token).getJSON(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name), &meta); err != nil {
		return nil, fmt.Errorf("%s: %w", p.name, err)
	}
	full := owner + "/" + name
	return []Repository{{Name: full, URL: cfg.Get("clone_url", giteaCloneURL(apiBase, owner, name))}}, nil
}
