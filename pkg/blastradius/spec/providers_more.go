package spec

import (
	"errors"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var (
	algoliaAppRe = regexp.MustCompile(`^[A-Za-z0-9]{6,32}$`)
	// auth0DomainRe accepts tenant hosts (acme.us.auth0.com) and custom
	// domains; it rejects ports, paths and userinfo so the client secret
	// never reaches an arbitrary origin through a crafted domain value.
	hostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)
)

func hostFromExtra(cred detectors.AccessCredential, key string) (string, error) {
	h := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(cred.Extra[key]), "https://"), "/")
	if !hostRe.MatchString(h) {
		return "", errors.New("credential JSON must include a valid " + key + " host")
	}
	return "https://" + h, nil
}

// Algolia maps an Algolia API key (Extra: application_id) to its ACLs and
// indexes.
var Algolia = Spec{
	Provider: "algolia",
	Base: func(c detectors.AccessCredential) (string, error) {
		app := c.Extra["application_id"]
		if !algoliaAppRe.MatchString(app) {
			return "", errors.New("credential JSON must include application_id")
		}
		return "https://" + strings.ToLower(app) + "-dsn.algolia.net", nil
	},
	Auth: func(c detectors.AccessCredential) (map[string]string, error) {
		return map[string]string{"X-Algolia-Application-Id": c.Extra["application_id"], "X-Algolia-API-Key": c.Secret}, nil
	},
	IdentityPath: "/1/keys/{secret}", NamePath: "description", TypeLiteral: "api_key", IDTemplate: "{extra.application_id}",
	ScopePath:        "acl",
	PrivilegedScopes: set("admin", "editSettings", "deleteIndex", "listIndexes", "addObject", "deleteObject"),
	Listings: []Listing{
		{Type: "index", Path: "/1/indexes", ItemsPath: "items", NamePath: "name"},
		{Type: "index_restriction", ItemsPath: "indexes"},
	},
	Notes: []string{"the admin API key is not readable through /1/keys; a failing identity call on a working key indicates the admin key"},
}

// Artifactory maps a JFrog access token (Extra: api_endpoint platform URL).
var Artifactory = Spec{
	Provider: "artifactory", RequireEndpoint: true, Auth: Bearer,
	IdentityPath: "/artifactory/api/security/current", IDPath: "name", NamePath: "email|name", TypeLiteral: "user",
	PrivilegedIdentity: func(d any, _ detectors.AccessCredential) bool { return Get(d, "admin") == true },
	ScopePath:          "groups",
	Listings: []Listing{
		{Type: "repository", Path: "/artifactory/api/repositories", NamePath: "key", PermPaths: []string{"type"}},
	},
	Activity: &Activity{Path: "/access/api/v1/tokens/me", LastUsedPath: "last_used", Service: "jfrog-access"},
}

// Xray maps a JFrog access token to Xray-indexed repositories and policies.
var Xray = Spec{
	Provider: "xray", RequireEndpoint: true, Auth: Bearer,
	IdentityPath: "/xray/api/v1/system/ping", TypeLiteral: "token",
	Listings: []Listing{
		{Type: "repository", Path: "/xray/api/v1/binMgr/default/repos", ItemsPath: "repos", NamePath: "name"},
		{Type: "policy", Path: "/xray/api/v1/policies", NamePath: "name", PermPaths: []string{"type"}},
	},
	Activity: &Activity{Path: "/access/api/v1/tokens/me", LastUsedPath: "last_used", Service: "jfrog-access"},
	Notes:    []string{"Xray does not expose the token's user; use the artifactory provider for identity"},
}

// Auth0 maps an Auth0 machine-to-machine client secret (Extra: client_id,
// domain) to its Management API grant, clients and APIs.
var Auth0 = Spec{
	Provider: "auth0",
	Base:     func(c detectors.AccessCredential) (string, error) { return hostFromExtra(c, "domain") },
	Exchange: &Exchange{Path: "/oauth/token", ScopePath: "scope",
		JSON: `{"client_id":"{extra.client_id}","client_secret":"{secret}","audience":"https://{extra.domain}/api/v2/","grant_type":"client_credentials"}`},
	TypeLiteral: "m2m_client", IDTemplate: "{extra.client_id}",
	PrivilegedScopes: set("create:clients", "update:clients", "delete:clients", "create:users", "update:users", "delete:users",
		"create:client_grants", "update:client_grants", "update:tenant_settings", "create:resource_servers", "update:resource_servers", "read:client_keys"),
	Listings: []Listing{
		{Type: "client", Path: "/api/v2/clients?fields=name,client_id&per_page=100", NamePath: "name|client_id"},
		{Type: "resource_server", Path: "/api/v2/resource-servers?per_page=100", NamePath: "identifier|name"},
	},
}

// IBMCloud maps an IBM Cloud API key to its IAM identity, account and
// resource instances.
var IBMCloud = Spec{
	Provider: "ibmcloud", BaseURL: "https://iam.cloud.ibm.com",
	Auth: Header("IAM-Apikey", "", nil),
	Exchange: &Exchange{Path: "/identity/token", KeepAuth: true,
		Form: "grant_type=urn%3Aibm%3Aparams%3Aoauth%3Agrant-type%3Aapikey&apikey={secret}"},
	IdentityPath: "/v1/apikeys/details", IDPath: "id", NamePath: "name|iam_id", TypeLiteral: "api_key", AccountPath: "account_id",
	Listings: []Listing{
		{Type: "resource_instance", Path: "https://resource-controller.cloud.ibm.com/v2/resource_instances?limit=100", ItemsPath: "resources",
			NamePath: "name|crn", Paginate: NextField, NextPath: "next_url"},
	},
	Activity: &Activity{Path: "/v1/apikeys/{id}?include_activity=true", LastUsedPath: "activity.last_authn", Service: "iam"},
	Notes:    []string{"IAM access policies are not evaluated; resource visibility approximates reach"},
}

// Monday maps a monday.com API token (GraphQL) to its user, account,
// workspaces and boards.
var Monday = Spec{
	Provider: "monday", BaseURL: "https://api.monday.com",
	Auth: func(c detectors.AccessCredential) (map[string]string, error) {
		return map[string]string{"Authorization": c.Secret}, nil
	},
	IdentityPath: "/v2", IdentityQuery: "query { me { id name email is_admin is_guest account { id name slug } } }",
	IDPath: "data.me.id", NamePath: "data.me.email|data.me.name", TypeLiteral: "user", AccountPath: "data.me.account.slug|data.me.account.id",
	PrivilegedIdentity: func(d any, _ detectors.AccessCredential) bool { return Get(d, "data.me.is_admin") == true },
	Listings: []Listing{
		{Type: "team", Query: "query { me { teams { id name } } }", ItemsPath: "data.me.teams", NamePath: "name|id"},
		{Type: "workspace", Query: "query { workspaces(limit: 100) { id name kind } }", ItemsPath: "data.workspaces", NamePath: "name|id", PermPaths: []string{"kind"}},
		{Type: "board", Query: "query { boards(limit: 100) { id name board_kind } }", ItemsPath: "data.boards", NamePath: "name|id", PermPaths: []string{"board_kind"}},
	},
	Notes: []string{"workspace and board listings read the first page only"},
}

// WeightsAndBiases maps a W&B API key (GraphQL) to its viewer and teams.
var WeightsAndBiases = Spec{
	Provider: "wandb", BaseURL: "https://api.wandb.ai",
	Auth: func(c detectors.AccessCredential) (map[string]string, error) {
		return BasicWithExtra("user", false)(detectors.AccessCredential{Secret: c.Secret, Extra: map[string]string{"user": "api"}})
	},
	IdentityPath: "/graphql", IdentityQuery: "query { viewer { id username email admin teams { edges { node { name } } } } }",
	IDPath: "data.viewer.id", NamePath: "data.viewer.username|data.viewer.email", TypeLiteral: "user",
	PrivilegedIdentity: func(d any, _ detectors.AccessCredential) bool { return Get(d, "data.viewer.admin") == true },
	Listings:           []Listing{{Type: "team", ItemsPath: "data.viewer.teams.edges", NamePath: "node.name"}},
	Notes:              []string{"W&B API keys carry the user's full permissions"},
}

func paypalBase(c detectors.AccessCredential) (string, error) {
	if strings.EqualFold(c.Extra["environment"], "sandbox") {
		return "https://api-m.sandbox.paypal.com", nil
	}
	return "https://api-m.paypal.com", nil
}

// PayPal maps a PayPal REST client id (secret) and client secret
// (secondary) to its OAuth scopes and merchant identity.
var PayPal = Spec{
	Provider: "paypal", Base: paypalBase,
	Exchange:    &Exchange{Path: "/v1/oauth2/token", Form: "grant_type=client_credentials", BasicUser: "{secret}", BasicPass: "{secondary}", ScopePath: "scope"},
	TypeLiteral: "rest_app", IDTemplate: "{secret}",
	PrivilegedScopes: set("https://uri.paypal.com/services/payments/payment", "https://uri.paypal.com/services/payments/refund",
		"https://uri.paypal.com/services/payments/payouts", "https://uri.paypal.com/services/vault/payment-tokens/readwrite",
		"https://uri.paypal.com/services/disputes/update-seller"),
	Listings: []Listing{{Type: "merchant", Path: "/v1/identity/oauth2/userinfo?schema=paypalv1.1", NamePath: "user_id|payer_id|email"}},
	Notes:    []string{"live credentials are assumed unless environment=sandbox"},
}

func plaidBase(c detectors.AccessCredential) (string, error) {
	switch strings.ToLower(c.Extra["environment"]) {
	case "sandbox":
		return "https://sandbox.plaid.com", nil
	case "development":
		return "https://development.plaid.com", nil
	}
	return "https://production.plaid.com", nil
}

// Plaid maps a Plaid client id (secret) and secret (secondary).
var Plaid = Spec{
	Provider: "plaid", Base: plaidBase,
	IdentityPath: "/institutions/get",
	IdentityBody: `{"client_id":"{secret}","secret":"{secondary}","count":100,"offset":0,"country_codes":["US"]}`,
	IDTemplate:   "{secret}", TypeLiteral: "client", AccountPath: "request_id",
	PrivilegedIdentity: func(_ any, c detectors.AccessCredential) bool {
		e := strings.ToLower(c.Extra["environment"])
		return e == "" || e == "production"
	},
	Listings: []Listing{{Type: "institution", ItemsPath: "institutions", NamePath: "name|institution_id"}},
	Notes:    []string{"production is probed unless environment is sandbox/development; linked Items need per-item access tokens"},
}

// Salesforce maps a Salesforce access token (Extra: api_endpoint instance
// URL) to its user, organization, permission sets and sObjects.
var Salesforce = Spec{
	Provider: "salesforce", RequireEndpoint: true, Auth: Bearer,
	IdentityPath: "/services/oauth2/userinfo", IDPath: "user_id", NamePath: "preferred_username|email", TypeLiteral: "user", AccountPath: "organization_id",
	Listings: []Listing{
		{Type: "permission_set",
			Path:      "/services/data/v60.0/query?q=SELECT+Name,PermissionsModifyAllData,PermissionsViewAllData,PermissionsManageUsers,PermissionsAuthorApex,PermissionsCustomizeApplication+FROM+PermissionSet+WHERE+Id+IN+(SELECT+PermissionSetId+FROM+PermissionSetAssignment+WHERE+AssigneeId='{id}')",
			ItemsPath: "records", NamePath: "Name",
			PermPaths:  []string{"PermissionsModifyAllData", "PermissionsViewAllData", "PermissionsManageUsers", "PermissionsAuthorApex", "PermissionsCustomizeApplication"},
			Privileged: anyOf("permissionsmodifyalldata", "permissionsmanageusers", "permissionsauthorapex"),
			Paginate:   NextField, NextPath: "nextRecordsUrl"},
		{Type: "sobject", Path: "/services/data/v60.0/sobjects", ItemsPath: "sobjects", NamePath: "name"},
	},
}
