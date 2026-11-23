// Package github maps a GitHub token to its user, OAuth scopes,
// organizations and repositories.
package github

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/blastradius/httpx"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// MaxRepos caps the paginated repository listing; exceeding it is recorded
// as a limitation.
const MaxRepos = 1000

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
		if strings.HasPrefix(cred.Secret, "ghs_") {
			return m.mapInstallation(ctx, base, hdr)
		}
		return nil, fmt.Errorf("github: identity: %w", err)
	}
	am := detectors.NewAccessMap("github")
	am.Identity = detectors.AccessIdentity{ID: fmt.Sprint(user.ID), Name: user.Login, Type: strings.ToLower(firstNonEmpty(user.Type, "user"))}
	switch {
	case strings.HasPrefix(cred.Secret, "github_pat_"):
		am.Identity.Type = "fine_grained_pat"
		am.Limitations = append(am.Limitations, "fine-grained token: repository permissions shown are the owner's role; the token's own permission set is not exposed by the API")
	case strings.HasPrefix(cred.Secret, "ghu_"):
		am.Identity.Type = "app_user_token"
		m.installations(ctx, base, hdr, am)
	}
	if exp := h.Get("GitHub-Authentication-Token-Expiration"); exp != "" {
		am.Limitations = append(am.Limitations, "token expires "+exp)
	}
	scopes := splitScopes(h.Get("X-OAuth-Scopes"))
	if h.Get("X-OAuth-Scopes") == "" && am.Identity.Type != "fine_grained_pat" {
		am.Limitations = append(am.Limitations, "token scopes not reported (fine-grained token); permissions are per-repository")
	}
	am.Permissions = scopes
	for _, s := range scopes {
		if privilegedScopes[s] {
			am.Privileged = true
		}
	}

	orgs, _, err := httpx.GetLinkPages[struct {
		Login string `json:"login"`
	}](ctx, m.Client, base+"/user/orgs?per_page=100", hdr, MaxRepos)
	if err != nil {
		am.Limitations = append(am.Limitations, "organizations: "+err.Error())
	}
	for _, o := range orgs {
		am.Resources = append(am.Resources, detectors.AccessResource{Type: "organization", Name: o.Login})
	}

	repos, truncated, err := httpx.GetLinkPages[struct {
		FullName    string          `json:"full_name"`
		Permissions map[string]bool `json:"permissions"`
	}](ctx, m.Client, base+"/user/repos?per_page=100", hdr, MaxRepos)
	if err != nil {
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
	if truncated {
		am.Limitations = append(am.Limitations, fmt.Sprintf("repository listing capped at %d", MaxRepos))
	}
	return am, nil
}

// privilegedAppPerms are GitHub App permissions whose write/admin level
// lets the token change code, CI, membership or settings.
var privilegedAppPerms = map[string]bool{
	"administration": true, "contents": true, "workflows": true, "members": true, "organization_administration": true,
	"secrets": true, "organization_secrets": true, "actions": true, "environments": true, "organization_self_hosted_runners": true,
}

func appPerms(p map[string]string) ([]string, bool) {
	out := []string{}
	priv := false
	for k, v := range p {
		out = append(out, k+":"+v)
		if privilegedAppPerms[k] && (v == "write" || v == "admin") {
			priv = true
		}
	}
	sort.Strings(out)
	return out, priv
}

type installRepo struct {
	FullName string `json:"full_name"`
}

// installations enumerates the GitHub App installations a user-to-server
// (ghu_) token reaches, with each installation's permissions and repos.
func (m Mapper) installations(ctx context.Context, base string, hdr map[string]string, am *detectors.AccessMap) {
	var inst struct {
		Installations []struct {
			ID          int64             `json:"id"`
			AppSlug     string            `json:"app_slug"`
			Permissions map[string]string `json:"permissions"`
			Account     struct {
				Login string `json:"login"`
			} `json:"account"`
		} `json:"installations"`
	}
	if _, err := httpx.GetJSON(ctx, m.Client, base+"/user/installations?per_page=100", hdr, &inst); err != nil {
		am.Limitations = append(am.Limitations, "installations: "+err.Error())
		return
	}
	for _, in := range inst.Installations {
		perms, priv := appPerms(in.Permissions)
		am.Privileged = am.Privileged || priv
		am.Resources = append(am.Resources, detectors.AccessResource{Type: "app_installation", Name: firstNonEmpty(in.AppSlug, fmt.Sprint(in.ID)) + "@" + in.Account.Login, Permissions: perms})
		var rr struct {
			Repositories []installRepo `json:"repositories"`
		}
		if _, err := httpx.GetJSON(ctx, m.Client, fmt.Sprintf("%s/user/installations/%d/repositories?per_page=100", base, in.ID), hdr, &rr); err != nil {
			am.Limitations = append(am.Limitations, fmt.Sprintf("installation %d repositories: %v", in.ID, err))
			continue
		}
		for _, r := range rr.Repositories {
			am.Resources = append(am.Resources, detectors.AccessResource{Type: "installation_repository", Name: r.FullName, Permissions: perms})
		}
	}
}

// mapInstallation maps a GitHub App installation token (ghs_), which has no
// user: identity and reach come from /installation/repositories.
func (m Mapper) mapInstallation(ctx context.Context, base string, hdr map[string]string) (*detectors.AccessMap, error) {
	var rr struct {
		TotalCount   int           `json:"total_count"`
		Repositories []installRepo `json:"repositories"`
	}
	h, err := httpx.GetJSON(ctx, m.Client, base+"/installation/repositories?per_page=100", hdr, &rr)
	if err != nil {
		return nil, fmt.Errorf("github: installation: %w", err)
	}
	am := detectors.NewAccessMap("github")
	am.Identity = detectors.AccessIdentity{Type: "app_installation"}
	for _, r := range rr.Repositories {
		am.Resources = append(am.Resources, detectors.AccessResource{Type: "installation_repository", Name: r.FullName})
		if am.Identity.Account == "" {
			am.Identity.Account, _, _ = strings.Cut(r.FullName, "/")
		}
	}
	if rr.TotalCount > len(rr.Repositories) {
		am.Limitations = append(am.Limitations, fmt.Sprintf("installation repository listing capped at %d of %d", len(rr.Repositories), rr.TotalCount))
	}
	if exp := h.Get("GitHub-Authentication-Token-Expiration"); exp != "" {
		am.Limitations = append(am.Limitations, "token expires "+exp)
	}
	am.Limitations = append(am.Limitations, "installation permissions require the app JWT and are not readable with the installation token")
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
