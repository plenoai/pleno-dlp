// Package gitlab maps a GitLab personal access token to its user, token
// scopes and member projects.
package gitlab

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/blastradius/httpx"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// MaxProjects caps the paginated project listing.
const MaxProjects = 1000

// Mapper implements detectors.AccessMapper for GitLab tokens.
type Mapper struct {
	BaseURL string // default https://gitlab.com; Extra["api_endpoint"] overrides
	Client  *http.Client
}

var privilegedScopes = map[string]bool{"api": true, "sudo": true, "admin_mode": true, "write_repository": true, "write_registry": true}

// accessLevels follows GitLab's documented member access levels.
var accessLevels = map[int]string{10: "guest", 15: "planner", 20: "reporter", 30: "developer", 40: "maintainer", 50: "owner"}

func (m Mapper) MapAccess(ctx context.Context, cred detectors.AccessCredential) (*detectors.AccessMap, error) {
	base := strings.TrimRight(cred.Extra["api_endpoint"], "/")
	if base == "" {
		base = strings.TrimRight(m.BaseURL, "/")
	}
	if base == "" {
		base = "https://gitlab.com"
	}
	hdr := map[string]string{"PRIVATE-TOKEN": cred.Secret}
	var user struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
		IsAdmin  bool   `json:"is_admin"`
		Bot      bool   `json:"bot"`
	}
	if _, err := httpx.GetJSON(ctx, m.Client, base+"/api/v4/user", hdr, &user); err != nil {
		return nil, fmt.Errorf("gitlab: identity: %w", err)
	}
	am := detectors.NewAccessMap("gitlab")
	typ := "user"
	if user.Bot {
		typ = "bot"
	}
	am.Identity = detectors.AccessIdentity{ID: fmt.Sprint(user.ID), Name: user.Username, Type: typ}
	am.Privileged = user.IsAdmin

	var tok struct {
		Scopes []string `json:"scopes"`
	}
	if _, err := httpx.GetJSON(ctx, m.Client, base+"/api/v4/personal_access_tokens/self", hdr, &tok); err != nil {
		am.Limitations = append(am.Limitations, "token scopes: "+err.Error())
	}
	if tok.Scopes != nil {
		am.Permissions = tok.Scopes
	}
	for _, s := range tok.Scopes {
		if privilegedScopes[s] {
			am.Privileged = true
		}
	}

	type project struct {
		PathWithNamespace string `json:"path_with_namespace"`
		Permissions       struct {
			ProjectAccess *struct {
				AccessLevel int `json:"access_level"`
			} `json:"project_access"`
			GroupAccess *struct {
				AccessLevel int `json:"access_level"`
			} `json:"group_access"`
		} `json:"permissions"`
	}
	projects, truncated, err := httpx.GetLinkPages[project](ctx, m.Client, base+"/api/v4/projects?membership=true&per_page=100", hdr, MaxProjects)
	if err != nil {
		am.Limitations = append(am.Limitations, "projects: "+err.Error())
	}
	for _, p := range projects {
		lvl := 0
		if a := p.Permissions.ProjectAccess; a != nil && a.AccessLevel > lvl {
			lvl = a.AccessLevel
		}
		if a := p.Permissions.GroupAccess; a != nil && a.AccessLevel > lvl {
			lvl = a.AccessLevel
		}
		res := detectors.AccessResource{Type: "project", Name: p.PathWithNamespace}
		if name, ok := accessLevels[lvl]; ok {
			res.Permissions = []string{name}
		}
		if lvl >= 40 {
			am.Privileged = true
		}
		am.Resources = append(am.Resources, res)
	}
	if truncated {
		am.Limitations = append(am.Limitations, fmt.Sprintf("project listing capped at %d", MaxProjects))
	}
	return am, nil
}
