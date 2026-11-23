// Package gcp maps a Google Cloud service-account key to its identity,
// the visible projects, and the IAM permissions it holds on its own project.
package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/plenoai/pleno-dlp/pkg/blastradius/httpx"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// ProbePermissions is the fixed set tested with projects.testIamPermissions.
// It covers IAM escalation and the most common data planes; it is a sample,
// not an exhaustive enumeration.
var ProbePermissions = []string{
	"resourcemanager.projects.get",
	"resourcemanager.projects.setIamPolicy",
	"iam.serviceAccounts.actAs",
	"iam.serviceAccountKeys.create",
	"iam.serviceAccounts.getAccessToken",
	"iam.roles.create",
	"storage.buckets.list",
	"storage.objects.get",
	"storage.objects.create",
	"compute.instances.list",
	"compute.instances.create",
	"secretmanager.versions.access",
	"cloudsql.instances.list",
	"bigquery.datasets.get",
	"container.clusters.get",
	"cloudfunctions.functions.create",
	"run.services.create",
}

var privileged = map[string]bool{
	"resourcemanager.projects.setIamPolicy": true,
	"iam.serviceAccounts.actAs":             true,
	"iam.serviceAccountKeys.create":         true,
	"iam.serviceAccounts.getAccessToken":    true,
	"iam.roles.create":                      true,
	"secretmanager.versions.access":         true,
}

// MaxProjects caps the project listing.
const MaxProjects = 100

// Mapper implements detectors.AccessMapper for GCP service-account keys. The
// credential Secret is the service-account JSON key.
type Mapper struct {
	ResourceManagerURL string // default https://cloudresourcemanager.googleapis.com
	TokenURL           string // overrides the key's token_uri (tests)
	Client             *http.Client
}

type keyFile struct {
	ClientEmail string `json:"client_email"`
	ClientID    string `json:"client_id"`
	ProjectID   string `json:"project_id"`
}

func (m Mapper) MapAccess(ctx context.Context, cred detectors.AccessCredential) (*detectors.AccessMap, error) {
	raw := []byte(cred.Secret)
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil || kf.ClientEmail == "" {
		return nil, errors.New("gcp: credential is not a service-account JSON key")
	}
	cfg, err := google.JWTConfigFromJSON(raw, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, fmt.Errorf("gcp: parse key: %w", err)
	}
	if m.TokenURL != "" {
		cfg.TokenURL = m.TokenURL
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpx.Client(m.Client))
	client := cfg.Client(ctx)
	if _, err := cfg.TokenSource(ctx).Token(); err != nil {
		return nil, fmt.Errorf("gcp: token exchange failed")
	}
	base := strings.TrimRight(m.ResourceManagerURL, "/")
	if base == "" {
		base = "https://cloudresourcemanager.googleapis.com"
	}

	am := detectors.NewAccessMap("gcp")
	am.Identity = detectors.AccessIdentity{ID: firstNonEmpty(kf.ClientID, kf.ClientEmail), Name: kf.ClientEmail, Type: "service_account", Account: kf.ProjectID}

	var list struct {
		Projects []struct {
			ProjectID string `json:"projectId"`
		} `json:"projects"`
		NextPageToken string `json:"nextPageToken"`
	}
	if _, err := httpx.GetJSON(ctx, client, fmt.Sprintf("%s/v1/projects?pageSize=%d", base, MaxProjects), nil, &list); err != nil {
		am.Limitations = append(am.Limitations, "project listing: "+err.Error())
	}
	if list.NextPageToken != "" {
		am.Limitations = append(am.Limitations, fmt.Sprintf("project listing capped at %d", MaxProjects))
	}
	projects := []string{}
	seen := map[string]bool{}
	if kf.ProjectID != "" {
		projects = append(projects, kf.ProjectID)
		seen[kf.ProjectID] = true
	}
	for _, p := range list.Projects {
		if !seen[p.ProjectID] {
			projects = append(projects, p.ProjectID)
			seen[p.ProjectID] = true
		}
	}

	all := map[string]bool{}
	for _, pid := range projects {
		granted, err := m.testPermissions(ctx, client, base, pid)
		if err != nil {
			am.Limitations = append(am.Limitations, fmt.Sprintf("testIamPermissions %s: %v", pid, err))
			am.Resources = append(am.Resources, detectors.AccessResource{Type: "project", Name: pid})
			continue
		}
		am.Resources = append(am.Resources, detectors.AccessResource{Type: "project", Name: pid, Permissions: granted})
		for _, g := range granted {
			if !all[g] {
				all[g] = true
				am.Permissions = append(am.Permissions, g)
			}
			if privileged[g] {
				am.Privileged = true
			}
		}
	}
	am.Limitations = append(am.Limitations, "permissions probed from a fixed sample via testIamPermissions; folder/organization bindings not enumerated")
	return am, nil
}

func (m Mapper) testPermissions(ctx context.Context, c *http.Client, base, project string) ([]string, error) {
	body, _ := json.Marshal(map[string][]string{"permissions": ProbePermissions})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/v1/projects/"+url.PathEscape(project)+":testIamPermissions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	var out struct {
		Permissions []string `json:"permissions"`
	}
	if _, err := httpx.Do(c, req, &out); err != nil {
		return nil, err
	}
	if out.Permissions == nil {
		out.Permissions = []string{}
	}
	return out.Permissions, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
