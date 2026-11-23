// Package github maps a GitHub token to its user, OAuth scopes,
// organizations and repositories.
package github

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/blastradius/httpx"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// MaxRepos caps the repository listing; exceeding it is recorded as a limitation.
const MaxRepos = 100

// Mapper implements detectors.AccessMapper for GitHub tokens.
type Mapper struct {
	BaseURL string // default https://api.github.com; Extra["api_endpoint"] overrides
	Client  *http.Client
}

var privilegedScopes = map[string]bool{
	"repo": true, "admin:org": true, "admin:enterprise": true, "delete_repo": true,
	"admin:repo_hook": true, "admin:org_hook": true, "workflow": true, "write:packages": true,
}

func (m Mapper) MapAccess(ctx context.Context, cred detectors.AccessCredential) (*detectors.AccessMap, error) {
	base := strings.TrimRight(firstNonEmpty(cred.Extra["api_endpoint"], m.BaseURL, "https://api.github.com"), "/")
	hdr := map[string]string{"Authorization": "Bearer " + cred.Secret, "X-GitHub-Api-Version": "2022-11-28"}
	var user struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
		Type  string `json:"type"`
	}
	h, err := httpx.GetJSON(ctx, m.Client, base+"/user", hdr, &user)
	if err != nil {
		return nil, fmt.Errorf("github: identity: %w", err)
	}
	am := detectors.NewAccessMap("github")
	am.Identity = detectors.AccessIdentity{ID: fmt.Sprint(user.ID), Name: user.Login, Type: strings.ToLower(firstNonEmpty(user.Type, "user"))}
	scopes := splitScopes(h.Get("X-OAuth-Scopes"))
	if h.Get("X-OAuth-Scopes") == "" {
		am.Limitations = append(am.Limitations, "token scopes not reported (fine-grained token); permissions are per-repository")
	}
	am.Permissions = scopes
	for _, s := range scopes {
		if privilegedScopes[s] {
			am.Privileged = true
		}
	}

	var orgs []struct {
		Login string `json:"login"`
	}
	if _, err := httpx.GetJSON(ctx, m.Client, base+"/user/orgs?per_page=100", hdr, &orgs); err != nil {
		am.Limitations = append(am.Limitations, "organizations: "+err.Error())
	}
	for _, o := range orgs {
		am.Resources = append(am.Resources, detectors.AccessResource{Type: "organization", Name: o.Login})
	}

	var repos []struct {
		FullName    string          `json:"full_name"`
		Permissions map[string]bool `json:"permissions"`
	}
	if _, err := httpx.GetJSON(ctx, m.Client, fmt.Sprintf("%s/user/repos?per_page=%d", base, MaxRepos), hdr, &repos); err != nil {
		am.Limitations = append(am.Limitations, "repositories: "+err.Error())
	}
	for _, r := range repos {
		res := detectors.AccessResource{Type: "repository", Name: r.FullName}
		for _, p := range []string{"admin", "maintain", "push", "triage", "pull"} {
			if r.Permissions[p] {
				res.Permissions = append(res.Permissions, p)
			}
		}
		if r.Permissions["admin"] {
			am.Privileged = true
		}
		am.Resources = append(am.Resources, res)
	}
	if len(repos) >= MaxRepos {
		am.Limitations = append(am.Limitations, fmt.Sprintf("repository listing capped at %d", MaxRepos))
	}
	return am, nil
}

func splitScopes(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
