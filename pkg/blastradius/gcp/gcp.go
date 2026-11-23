// Package gcp maps a Google Cloud service-account key to its identity, the
// visible projects, the sampled IAM permissions it holds on each project and
// on every folder/organization ancestor, and the service accounts it can
// impersonate.
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

// HierarchyProbePermissions are tested on every folder and organization
// ancestor of a visible project; bindings there inherit to all descendants.
var HierarchyProbePermissions = []string{
	"resourcemanager.folders.get",
	"resourcemanager.folders.setIamPolicy",
	"resourcemanager.organizations.get",
	"resourcemanager.organizations.setIamPolicy",
	"resourcemanager.projects.create",
	"resourcemanager.projects.setIamPolicy",
	"iam.serviceAccounts.actAs",
	"iam.serviceAccountKeys.create",
	"orgpolicy.policy.set",
}

// ImpersonationProbePermissions are tested on each visible service account.
var ImpersonationProbePermissions = []string{
	"iam.serviceAccounts.getAccessToken",
	"iam.serviceAccounts.signJwt",
	"iam.serviceAccounts.signBlob",
	"iam.serviceAccounts.implicitDelegation",
	"iam.serviceAccounts.actAs",
	"iam.serviceAccountKeys.create",
}

var impersonationPrivileged = map[string]bool{
	"iam.serviceAccounts.getAccessToken":     true,
	"iam.serviceAccounts.signJwt":            true,
	"iam.serviceAccounts.signBlob":           true,
	"iam.serviceAccounts.implicitDelegation": true,
	"iam.serviceAccountKeys.create":          true,
}

// MaxProjects caps the paginated project listing; MaxServiceAccounts caps
// the service accounts probed for impersonation across all projects.
const (
	MaxProjects        = 1000
	MaxServiceAccounts = 200
)

// Mapper implements detectors.AccessMapper for GCP service-account keys. The
// credential Secret is the service-account JSON key.
type Mapper struct {
	ResourceManagerURL string // default https://cloudresourcemanager.googleapis.com
	IAMURL             string // default https://iam.googleapis.com
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

	iamBase := strings.TrimRight(firstNonEmpty(m.IAMURL, "https://iam.googleapis.com"), "/")

	projects := []string{}
	seen := map[string]bool{}
	if kf.ProjectID != "" {
		projects = append(projects, kf.ProjectID)
		seen[kf.ProjectID] = true
	}
	token := ""
	for {
		var list struct {
			Projects []struct {
				ProjectID string `json:"projectId"`
			} `json:"projects"`
			NextPageToken string `json:"nextPageToken"`
		}
		u := base + "/v1/projects?pageSize=500"
		if token != "" {
			u += "&pageToken=" + url.QueryEscape(token)
		}
		if _, err := httpx.GetJSON(ctx, client, u, nil, &list); err != nil {
			am.Limitations = append(am.Limitations, "project listing: "+err.Error())
			break
		}
		for _, p := range list.Projects {
			if !seen[p.ProjectID] {
				projects = append(projects, p.ProjectID)
				seen[p.ProjectID] = true
			}
		}
		if list.NextPageToken == "" || list.NextPageToken == token {
			break
		}
		if len(projects) >= MaxProjects {
			am.Limitations = append(am.Limitations, fmt.Sprintf("project listing capped at %d", MaxProjects))
			break
		}
		token = list.NextPageToken
	}
	if len(projects) > MaxProjects {
		projects = projects[:MaxProjects]
	}

	all := map[string]bool{}
	record := func(granted []string, priv map[string]bool) {
		for _, g := range granted {
			if !all[g] {
				all[g] = true
				am.Permissions = append(am.Permissions, g)
			}
			if priv[g] {
				am.Privileged = true
			}
		}
	}
	ancestors := map[string]bool{}
	var ancestorOrder []string
	for _, pid := range projects {
		granted, err := m.testPermissions(ctx, client, base+"/v1/projects/"+url.PathEscape(pid), ProbePermissions)
		if err != nil {
			am.Limitations = append(am.Limitations, fmt.Sprintf("testIamPermissions %s: %v", pid, err))
			am.Resources = append(am.Resources, detectors.AccessResource{Type: "project", Name: pid})
		} else {
			am.Resources = append(am.Resources, detectors.AccessResource{Type: "project", Name: pid, Permissions: granted})
			record(granted, privileged)
		}
		anc, err := m.ancestry(ctx, client, base, pid)
		if err != nil {
			am.Limitations = append(am.Limitations, fmt.Sprintf("getAncestry %s: %v", pid, err))
			continue
		}
		for _, a := range anc {
			if !ancestors[a] {
				ancestors[a] = true
				ancestorOrder = append(ancestorOrder, a)
			}
		}
	}
	// Folder and organization ancestors: inherited bindings.
	for _, a := range ancestorOrder {
		typ := strings.TrimSuffix(strings.SplitN(a, "/", 2)[0], "s")
		granted, err := m.testPermissions(ctx, client, base+"/v3/"+a, HierarchyProbePermissions)
		if err != nil {
			am.Limitations = append(am.Limitations, fmt.Sprintf("testIamPermissions %s: %v", a, err))
			am.Resources = append(am.Resources, detectors.AccessResource{Type: typ, Name: a})
			continue
		}
		am.Resources = append(am.Resources, detectors.AccessResource{Type: typ, Name: a, Permissions: granted})
		record(granted, map[string]bool{
			"resourcemanager.folders.setIamPolicy":       true,
			"resourcemanager.organizations.setIamPolicy": true,
			"resourcemanager.projects.setIamPolicy":      true,
			"iam.serviceAccounts.actAs":                  true,
			"iam.serviceAccountKeys.create":              true,
			"orgpolicy.policy.set":                       true,
		})
	}
	// Impersonation paths: service accounts this identity can mint tokens
	// for, sign as, or create keys on.
	probed := 0
	for _, pid := range projects {
		if probed >= MaxServiceAccounts {
			am.Limitations = append(am.Limitations, fmt.Sprintf("impersonation probing capped at %d service accounts", MaxServiceAccounts))
			break
		}
		sas, err := m.serviceAccounts(ctx, client, iamBase, pid, MaxServiceAccounts-probed)
		if err != nil {
			am.Limitations = append(am.Limitations, fmt.Sprintf("serviceAccounts %s: %v", pid, err))
			continue
		}
		for _, sa := range sas {
			probed++
			if sa == kf.ClientEmail {
				continue
			}
			granted, err := m.testPermissions(ctx, client, iamBase+"/v1/projects/-/serviceAccounts/"+url.PathEscape(sa), ImpersonationProbePermissions)
			if err != nil || len(granted) == 0 {
				continue
			}
			am.Resources = append(am.Resources, detectors.AccessResource{Type: "impersonable_service_account", Name: sa, Permissions: granted})
			for _, g := range granted {
				if impersonationPrivileged[g] {
					am.Privileged = true
				}
			}
		}
	}
	am.Limitations = append(am.Limitations, "permissions probed from fixed samples via testIamPermissions; role bindings are not read")
	return am, nil
}

// ancestry returns the folder/organization ancestors of a project as
// "folders/<id>" / "organizations/<id>", nearest first.
func (m Mapper) ancestry(ctx context.Context, c *http.Client, base, project string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/projects/"+url.PathEscape(project)+":getAncestry", strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	var out struct {
		Ancestor []struct {
			ResourceID struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"resourceId"`
		} `json:"ancestor"`
	}
	if _, err := httpx.Do(c, req, &out); err != nil {
		return nil, err
	}
	var res []string
	for _, a := range out.Ancestor {
		switch a.ResourceID.Type {
		case "folder":
			res = append(res, "folders/"+a.ResourceID.ID)
		case "organization":
			res = append(res, "organizations/"+a.ResourceID.ID)
		}
	}
	return res, nil
}

func (m Mapper) serviceAccounts(ctx context.Context, c *http.Client, iamBase, project string, limit int) ([]string, error) {
	var out []string
	token := ""
	for len(out) < limit {
		u := iamBase + "/v1/projects/" + url.PathEscape(project) + "/serviceAccounts?pageSize=100"
		if token != "" {
			u += "&pageToken=" + url.QueryEscape(token)
		}
		var page struct {
			Accounts []struct {
				Email string `json:"email"`
			} `json:"accounts"`
			NextPageToken string `json:"nextPageToken"`
		}
		if _, err := httpx.GetJSON(ctx, c, u, nil, &page); err != nil {
			return out, err
		}
		for _, a := range page.Accounts {
			out = append(out, a.Email)
		}
		if page.NextPageToken == "" || page.NextPageToken == token {
			break
		}
		token = page.NextPageToken
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// testPermissions calls <resource>:testIamPermissions with perms.
func (m Mapper) testPermissions(ctx context.Context, c *http.Client, resource string, perms []string) ([]string, error) {
	body, _ := json.Marshal(map[string][]string{"permissions": perms})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, resource+":testIamPermissions", bytes.NewReader(body))
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
