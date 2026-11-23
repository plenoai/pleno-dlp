package detectors

import "context"

// AccessMapSchemaVersion identifies the JSON shape of AccessMap. Bump it on
// any breaking field change so downstream consumers can route by version.
const AccessMapSchemaVersion = "pleno-dlp.access-map/v1"

// AccessMapper is optionally implemented beside Verifier by components that
// can resolve a confirmed credential into the identity it authenticates as,
// the permissions it holds, and the resources it can reach ("blast radius").
// Mapping performs additional authenticated network requests, so callers must
// only invoke it when the operator opted in (scan --blast-radius or the
// standalone blast-radius command).
type AccessMapper interface {
	MapAccess(ctx context.Context, cred AccessCredential) (*AccessMap, error)
}

// AccessCredential carries the credential material a mapper needs. Secret is
// the primary token (Result.Raw for single-part credentials); Secondary holds
// the paired value for two-part credentials (for example the AWS secret access
// key, with Secret being the access key id). Extra carries provider-specific
// inputs such as an API endpoint.
type AccessCredential struct {
	Secret    string            `json:"secret"`
	Secondary string            `json:"secondary,omitempty"`
	Extra     map[string]string `json:"extra,omitempty"`
}

// AccessMap is the provider-neutral blast-radius result.
type AccessMap struct {
	Schema      string           `json:"schema"`
	Provider    string           `json:"provider"`
	Identity    AccessIdentity   `json:"identity"`
	Permissions []string         `json:"permissions"`
	Resources   []AccessResource `json:"resources"`
	// Privileged is true when the recorded permissions include
	// administrative or account-wide write scope.
	Privileged bool `json:"privileged"`
	// Limitations lists what the mapper could not enumerate (missing
	// permission, pagination cap, ...). An empty list does not prove the
	// view is complete; a non-empty list proves it is not.
	Limitations []string `json:"limitations"`
	// Activity records when the provider last saw the credential used, for
	// providers that expose it (AWS GetAccessKeyLastUsed, ...). Omitted when
	// unknown; additive within v1.
	Activity *AccessActivity `json:"activity,omitempty"`
}

// AccessActivity is the provider-reported last use of a credential.
type AccessActivity struct {
	LastUsed string `json:"last_used,omitempty"` // RFC 3339
	Service  string `json:"service,omitempty"`
	Region   string `json:"region,omitempty"`
}

// AccessIdentity describes who or what the credential authenticates as.
type AccessIdentity struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	Type    string `json:"type"`
	Account string `json:"account,omitempty"`
}

// AccessResource is one reachable resource and the permissions recorded on it.
type AccessResource struct {
	Type        string   `json:"type"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions,omitempty"`
}

// NewAccessMap returns an AccessMap with the schema stamped and slices
// non-nil so JSON consumers always see arrays.
func NewAccessMap(provider string) *AccessMap {
	return &AccessMap{
		Schema:      AccessMapSchemaVersion,
		Provider:    provider,
		Permissions: []string{},
		Resources:   []AccessResource{},
		Limitations: []string{},
	}
}
