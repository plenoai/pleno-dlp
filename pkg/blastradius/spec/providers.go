package spec

import (
	"slices"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func anyOf(set ...string) func([]string) bool {
	return func(perms []string) bool {
		for _, p := range perms {
			if slices.Contains(set, strings.ToLower(p)) {
				return true
			}
		}
		return false
	}
}

func set(v ...string) map[string]bool {
	m := map[string]bool{}
	for _, s := range v {
		m[s] = true
	}
	return m
}

// OpenAI maps an OpenAI API key to its user and organization memberships.
var OpenAI = Spec{
	Provider: "openai", BaseURL: "https://api.openai.com", Auth: Bearer,
	IdentityPath: "/v1/me", IDPath: "id", NamePath: "email", TypeLiteral: "user",
	Listings: []Listing{
		{Type: "organization", ItemsPath: "orgs.data", NamePath: "title|name|id", PermPaths: []string{"role"}, Privileged: anyOf("owner")},
		{Type: "project", Path: "/v1/organization/projects?limit=100", ItemsPath: "data", NamePath: "name|id", Paginate: NoPages},
	},
	Notes: []string{"project listing requires an admin key; per-project key permissions are not exposed"},
}

// Anthropic maps an Anthropic API key to the models it can reach and, for
// admin keys, its organization.
var Anthropic = Spec{
	Provider: "anthropic", BaseURL: "https://api.anthropic.com",
	Auth:         Header("x-api-key", "", map[string]string{"anthropic-version": "2023-06-01"}),
	IdentityPath: "/v1/models?limit=1000", TypeLiteral: "api_key",
	PrivilegedIdentity: func(_ any, c detectors.AccessCredential) bool { return strings.HasPrefix(c.Secret, "sk-ant-admin") },
	Listings: []Listing{
		{Type: "model", ItemsPath: "data", NamePath: "id"},
		{Type: "workspace", Path: "/v1/organizations/workspaces?limit=100", ItemsPath: "data", NamePath: "name|id", Paginate: NoPages},
	},
	Notes: []string{"standard API keys do not expose organization identity; workspace listing requires an admin key"},
}

// HuggingFace maps a Hugging Face token to its user, token role and org roles.
var HuggingFace = Spec{
	Provider: "huggingface", BaseURL: "https://huggingface.co", Auth: Bearer,
	IdentityPath: "/api/whoami-v2", IDPath: "id", NamePath: "name", TypePath: "type",
	ScopePath:        "auth.accessToken.role",
	PrivilegedScopes: set("write", "admin"),
	Listings: []Listing{
		{Type: "organization", ItemsPath: "orgs", NamePath: "name", PermPaths: []string{"roleInOrg"}, Privileged: anyOf("admin", "write")},
	},
}

// Buildkite maps a Buildkite API token to its user, scopes and organizations.
var Buildkite = Spec{
	Provider: "buildkite", BaseURL: "https://api.buildkite.com", Auth: Bearer,
	IdentityPath: "/v2/user", IDPath: "id", NamePath: "email|name", TypeLiteral: "user",
	ScopeEndpoint: "/v2/access-token", ScopeEndpointPath: "scopes",
	PrivilegedScopes: set("write_pipelines", "write_builds", "write_agents", "write_teams", "write_suites", "graphql"),
	Listings: []Listing{
		{Type: "organization", Path: "/v2/organizations?per_page=100", NamePath: "slug", Paginate: LinkHeader},
	},
}

// Harness maps a Harness API key to its user and accounts.
var Harness = Spec{
	Provider: "harness", BaseURL: "https://app.harness.io", Auth: Header("x-api-key", "", nil),
	IdentityPath: "/ng/api/user/currentUser", IDPath: "data.uuid", NamePath: "data.email", TypeLiteral: "user",
	AccountPath:        "data.defaultAccountId",
	PrivilegedIdentity: func(d any, _ detectors.AccessCredential) bool { return Get(d, "data.admin") == true },
	Listings: []Listing{
		{Type: "account", ItemsPath: "data.accounts", NamePath: "accountName|uuid"},
	},
	Notes: []string{"Harness RBAC role bindings are not enumerated"},
}

// Gitea maps a Gitea/Forgejo token (self-hosted; api_endpoint required).
var Gitea = Spec{
	Provider: "gitea", RequireEndpoint: true, Auth: Header("Authorization", "token ", nil),
	IdentityPath: "/api/v1/user", IDPath: "id", NamePath: "login", TypeLiteral: "user",
	PrivilegedIdentity: func(d any, _ detectors.AccessCredential) bool { return Get(d, "is_admin") == true },
	Listings: []Listing{
		{Type: "organization", Path: "/api/v1/user/orgs?limit=50", NamePath: "username|name", Paginate: PageParam, PageParam: "page"},
		{Type: "repository", Path: "/api/v1/user/repos?limit=50", NamePath: "full_name",
			PermPaths: []string{"permissions.admin", "permissions.push", "permissions.pull"}, Privileged: anyOf("admin"),
			Paginate: PageParam, PageParam: "page"},
	},
}

// Bitbucket maps a Bitbucket Cloud access token (or username + app password
// via Extra["username"]) to its user, scopes and workspaces.
var Bitbucket = Spec{
	Provider: "bitbucket", BaseURL: "https://api.bitbucket.org", Auth: BasicWithExtra("username", true),
	IdentityPath: "/2.0/user", IDPath: "uuid", NamePath: "username|display_name", TypePath: "type",
	ScopeHeader:      "X-OAuth-Scopes",
	PrivilegedScopes: set("admin", "account:write", "repository:admin", "repository:delete", "project:admin", "pipeline:write", "webhook"),
	Listings: []Listing{
		{Type: "workspace", Path: "/2.0/user/permissions/workspaces?pagelen=100", ItemsPath: "values", NamePath: "workspace.slug",
			PermPaths: []string{"permission"}, Privileged: anyOf("owner"), Paginate: NextField, NextPath: "next"},
		{Type: "repository", Path: "/2.0/user/permissions/repositories?pagelen=100", ItemsPath: "values", NamePath: "repository.full_name",
			PermPaths: []string{"permission"}, Privileged: anyOf("admin"), Paginate: NextField, NextPath: "next"},
	},
}

// DigitalOcean maps a DigitalOcean token to its account and team.
var DigitalOcean = Spec{
	Provider: "digitalocean", BaseURL: "https://api.digitalocean.com", Auth: Bearer,
	IdentityPath: "/v2/account", IDPath: "account.uuid", NamePath: "account.email", TypeLiteral: "user",
	AccountPath: "account.team.uuid",
	Listings: []Listing{
		{Type: "project", Path: "/v2/projects?per_page=200", ItemsPath: "projects", NamePath: "name|id", Paginate: NextField, NextPath: "links.pages.next"},
		{Type: "droplet", Path: "/v2/droplets?per_page=200", ItemsPath: "droplets", NamePath: "name|id", Paginate: NextField, NextPath: "links.pages.next"},
	},
	Notes: []string{"token read/write scope is not exposed by the API"},
}

// SendGrid maps a SendGrid API key to its user and granted scopes.
var SendGrid = Spec{
	Provider: "sendgrid", BaseURL: "https://api.sendgrid.com", Auth: Bearer,
	IdentityPath: "/v3/user/username", IDPath: "user_id", NamePath: "username", TypeLiteral: "api_key",
	ScopeEndpoint: "/v3/scopes", ScopeEndpointPath: "scopes",
	PrivilegedScopes: set("api_keys.create", "api_keys.update", "teammates.create", "subusers.create", "user.account.update"),
}

// Stripe maps a Stripe secret/restricted key to its account.
var Stripe = Spec{
	Provider: "stripe", BaseURL: "https://api.stripe.com", Auth: BasicSecretUser,
	IdentityPath: "/v1/account", IDPath: "id", NamePath: "business_profile.name|email", TypeLiteral: "account",
	PrivilegedIdentity: func(_ any, c detectors.AccessCredential) bool { return strings.HasPrefix(c.Secret, "sk_live_") },
	Notes:              []string{"restricted key (rk_) permissions are not exposed by the API"},
}

// CircleCI maps a CircleCI personal token to its user and collaborations.
var CircleCI = Spec{
	Provider: "circleci", BaseURL: "https://circleci.com", Auth: Header("Circle-Token", "", nil),
	IdentityPath: "/api/v2/me", IDPath: "id", NamePath: "login|name", TypeLiteral: "user",
	Listings: []Listing{
		{Type: "organization", Path: "/api/v2/me/collaborations", NamePath: "slug|name"},
	},
}

// TerraformCloud maps an HCP Terraform user/team token.
var TerraformCloud = Spec{
	Provider: "terraformcloud", BaseURL: "https://app.terraform.io",
	Auth: func(c detectors.AccessCredential) (map[string]string, error) {
		return map[string]string{"Authorization": "Bearer " + c.Secret, "Content-Type": "application/vnd.api+json"}, nil
	},
	IdentityPath: "/api/v2/account/details", IDPath: "data.id", NamePath: "data.attributes.username|data.attributes.email", TypePath: "data.type",
	Listings: []Listing{
		{Type: "organization", Path: "/api/v2/organizations?page%5Bsize%5D=100", ItemsPath: "data", NamePath: "attributes.name|id",
			PermPaths: []string{"attributes.permissions.can-destroy", "attributes.permissions.can-update"}, Privileged: anyOf("can-destroy"),
			Paginate: NextField, NextPath: "links.next"},
	},
}

// Jira maps an Atlassian API token (Extra: api_endpoint site URL, email).
var Jira = Spec{
	Provider: "jira", RequireEndpoint: true, Auth: BasicWithExtra("email", true),
	IdentityPath: "/rest/api/3/myself", IDPath: "accountId", NamePath: "emailAddress|displayName", TypePath: "accountType",
	ScopeEndpoint: "/rest/api/3/mypermissions?permissions=ADMINISTER,ADMINISTER_PROJECTS,BROWSE_PROJECTS,CREATE_ISSUES", ScopeEndpointPath: "permissions",
	Listings: []Listing{
		{Type: "project", Path: "/rest/api/3/project/search?maxResults=50", ItemsPath: "values", NamePath: "key|name", Paginate: NextField, NextPath: "nextPage"},
	},
}

// Confluence maps an Atlassian API token to Confluence spaces.
var Confluence = Spec{
	Provider: "confluence", RequireEndpoint: true, Auth: BasicWithExtra("email", true),
	IdentityPath: "/wiki/rest/api/user/current", IDPath: "accountId", NamePath: "email|publicName|displayName", TypePath: "accountType",
	Listings: []Listing{
		{Type: "space", Path: "/wiki/rest/api/space?limit=100", ItemsPath: "results", NamePath: "key|name", Paginate: OffsetParam, PageParam: "start"},
	},
}

// Pinecone maps a Pinecone API key to its indexes.
var Pinecone = Spec{
	Provider: "pinecone", BaseURL: "https://api.pinecone.io",
	Auth:         Header("Api-Key", "", map[string]string{"X-Pinecone-API-Version": "2024-07"}),
	IdentityPath: "/indexes", TypeLiteral: "api_key",
	Listings: []Listing{{Type: "index", ItemsPath: "indexes", NamePath: "name"}},
	Notes:    []string{"Pinecone API keys carry project-wide access; identity is not exposed"},
}

// Asana maps an Asana PAT to its user and workspaces.
var Asana = Spec{
	Provider: "asana", BaseURL: "https://app.asana.com", Auth: Bearer,
	IdentityPath: "/api/1.0/users/me", IDPath: "data.gid", NamePath: "data.email|data.name", TypeLiteral: "user",
	Listings: []Listing{{Type: "workspace", ItemsPath: "data.workspaces", NamePath: "name|gid"}},
}

// Fastly maps a Fastly API token to its user, role and token scopes.
var Fastly = Spec{
	Provider: "fastly", BaseURL: "https://api.fastly.com", Auth: Header("Fastly-Key", "", nil),
	IdentityPath: "/current_user", IDPath: "id", NamePath: "login|name", TypeLiteral: "user", AccountPath: "customer_id",
	ScopeEndpoint: "/tokens/self", ScopeEndpointPath: "scopes",
	PrivilegedScopes: set("global"),
	PrivilegedIdentity: func(d any, _ detectors.AccessCredential) bool {
		r := str(Get(d, "role"))
		return r == "superuser" || r == "engineer"
	},
}

// Airtable maps an Airtable PAT to its user, scopes and bases.
var Airtable = Spec{
	Provider: "airtable", BaseURL: "https://api.airtable.com", Auth: Bearer,
	IdentityPath: "/v0/meta/whoami", IDPath: "id", NamePath: "email|id", TypeLiteral: "user", ScopePath: "scopes",
	PrivilegedScopes: set("schema.bases:write", "workspacesAndBases:write", "enterprise.user:write"),
	Listings: []Listing{{Type: "base", Path: "/v0/meta/bases", ItemsPath: "bases", NamePath: "name|id",
		PermPaths: []string{"permissionLevel"}, Privileged: anyOf("create", "owner")}},
	Notes: []string{"base listing reads the first page only"},
}

// HubSpot maps a HubSpot private-app token to its portal.
var HubSpot = Spec{
	Provider: "hubspot", BaseURL: "https://api.hubapi.com", Auth: Bearer,
	IdentityPath: "/account-info/v3/details", IDPath: "portalId", NamePath: "uiDomain|portalId", TypeLiteral: "private_app", AccountPath: "portalId",
	Notes: []string{"private-app scopes are not exposed by a GET endpoint"},
}

// Square maps a Square access token to its merchant and locations.
var Square = Spec{
	Provider: "square", BaseURL: "https://connect.squareup.com",
	Auth: func(c detectors.AccessCredential) (map[string]string, error) {
		return map[string]string{"Authorization": "Bearer " + c.Secret, "Square-Version": "2024-07-17"}, nil
	},
	IdentityPath: "/v2/merchants/me", IDPath: "merchant.id", NamePath: "merchant.business_name|merchant.id", TypeLiteral: "merchant",
	PrivilegedIdentity: func(_ any, c detectors.AccessCredential) bool { return strings.HasPrefix(c.Secret, "EAAA") },
	Listings:           []Listing{{Type: "location", Path: "/v2/locations", ItemsPath: "locations", NamePath: "name|id"}},
	Notes:              []string{"OAuth scopes of personal access tokens are not exposed"},
}

// Brevo maps a Brevo (Sendinblue) API key to its account.
var Brevo = Spec{
	Provider: "brevo", BaseURL: "https://api.brevo.com", Auth: Header("api-key", "", nil),
	IdentityPath: "/v3/account", IDPath: "email", NamePath: "email|companyName", TypeLiteral: "account", AccountPath: "companyName",
	Notes:              []string{"Brevo API keys carry full account access"},
	PrivilegedIdentity: func(any, detectors.AccessCredential) bool { return true },
}

// Zendesk maps a Zendesk API token (Extra: api_endpoint, email).
var Zendesk = Spec{
	Provider: "zendesk", RequireEndpoint: true,
	Auth: func(c detectors.AccessCredential) (map[string]string, error) {
		if c.Extra["email"] == "" {
			return Bearer(c)
		}
		return BasicWithExtra("email", false)(detectors.AccessCredential{Secret: c.Secret, Extra: map[string]string{"email": c.Extra["email"] + "/token"}})
	},
	IdentityPath: "/api/v2/users/me.json", IDPath: "user.id", NamePath: "user.email|user.name", TypeLiteral: "user", ScopePath: "user.role",
	PrivilegedScopes: set("admin"),
}

// AzureDevOps maps an Azure DevOps PAT to its profile.
var AzureDevOps = Spec{
	Provider: "azure-devops", BaseURL: "https://app.vssps.visualstudio.com",
	Auth: func(c detectors.AccessCredential) (map[string]string, error) {
		return BasicWithExtra("user", false)(detectors.AccessCredential{Secret: c.Secret, Extra: map[string]string{"user": "pat"}})
	},
	IdentityPath: "/_apis/profile/profiles/me?api-version=7.1", IDPath: "id", NamePath: "emailAddress|displayName", TypeLiteral: "user",
	Notes: []string{"organization memberships and PAT scopes are not enumerated"},
}

// Shopify maps a Shopify Admin API token (Extra: api_endpoint shop URL).
var Shopify = Spec{
	Provider: "shopify", RequireEndpoint: true, Auth: Header("X-Shopify-Access-Token", "", nil),
	IdentityPath: "/admin/oauth/access_scopes.json", TypeLiteral: "app", ScopePath: "access_scopes",
	PrivilegedIdentity: func(d any, _ detectors.AccessCredential) bool {
		for _, s := range strs(Get(d, "access_scopes")) {
			if strings.HasPrefix(s, "write_") {
				return true
			}
		}
		return false
	},
}

// All lists every spec provider with the detectors it maps.
var All = []struct {
	Spec      Spec
	Detectors []detectors.DetectorType
}{
	{OpenAI, []detectors.DetectorType{detectors.OpenAI}},
	{Anthropic, []detectors.DetectorType{detectors.Anthropic}},
	{HuggingFace, []detectors.DetectorType{detectors.HuggingFace}},
	{Buildkite, []detectors.DetectorType{detectors.Buildkite}},
	{Harness, []detectors.DetectorType{detectors.Harness}},
	{Gitea, []detectors.DetectorType{detectors.Gitea}},
	{Bitbucket, []detectors.DetectorType{detectors.BitbucketCloud}},
	{DigitalOcean, []detectors.DetectorType{detectors.DigitalOcean}},
	{SendGrid, []detectors.DetectorType{detectors.SendGrid}},
	{Stripe, []detectors.DetectorType{detectors.Stripe}},
	{CircleCI, []detectors.DetectorType{detectors.CircleCI}},
	{TerraformCloud, []detectors.DetectorType{detectors.TerraformCloud}},
	{Jira, []detectors.DetectorType{detectors.Jira, detectors.Atlassian}},
	{Confluence, []detectors.DetectorType{detectors.Confluence}},
	{Pinecone, []detectors.DetectorType{detectors.Pinecone}},
	{Asana, []detectors.DetectorType{detectors.Asana}},
	{Fastly, []detectors.DetectorType{detectors.Fastly}},
	{Airtable, []detectors.DetectorType{detectors.Airtable}},
	{HubSpot, []detectors.DetectorType{detectors.HubSpot}},
	{Square, []detectors.DetectorType{detectors.Square}},
	{Brevo, []detectors.DetectorType{detectors.Brevo}},
	{Zendesk, []detectors.DetectorType{detectors.Zendesk}},
	{AzureDevOps, []detectors.DetectorType{detectors.AzureDevOps}},
	{Shopify, []detectors.DetectorType{detectors.Shopify}},
}
