// Package spec implements table-driven blast-radius mappers for providers
// whose access model is "one identity endpoint plus a few listing
// endpoints". Each provider is a Spec value: an authentication header
// builder, JSON dot paths for identity fields, optional scope sources, and
// paginated resource listings. Providers with richer models (AWS policy
// evaluation, GCP hierarchy) keep dedicated packages.
package spec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/blastradius/httpx"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// DefaultMaxItems caps each paginated resource listing.
const DefaultMaxItems = 1000

// Pagination selects how a listing advances.
type Pagination int

const (
	// NoPages fetches a single document.
	NoPages Pagination = iota
	// LinkHeader follows RFC 8288 Link rel="next".
	LinkHeader
	// NextField follows an absolute URL found at Listing.NextPath.
	NextField
	// PageParam increments the Listing.PageParam query value from 1 until a
	// page returns no items.
	PageParam
	// OffsetParam advances Listing.PageParam by the number of items received.
	OffsetParam
)

// Listing enumerates one resource type.
type Listing struct {
	Type      string // AccessResource.Type
	Path      string // request path (relative to the base URL); "" reuses the identity document
	ItemsPath string // dot path to the item array; "" means the document is the array
	NamePath  string // dot path inside an item for the resource name; "|"-separated fallbacks
	// PermPaths are dot paths inside an item. A string value is recorded as
	// a permission; a true boolean records the last path segment; an array
	// of strings records each element.
	PermPaths  []string
	Privileged func(perms []string) bool
	Paginate   Pagination
	NextPath   string // NextField
	PageParam  string // PageParam/OffsetParam query key
}

// Spec describes one provider.
type Spec struct {
	Provider string
	BaseURL  string
	// RequireEndpoint makes Extra["api_endpoint"] (or "base_url") mandatory,
	// for self-hosted or per-tenant providers.
	RequireEndpoint bool
	// Auth returns request headers for the credential.
	Auth         func(cred detectors.AccessCredential) (map[string]string, error)
	IdentityPath string
	IDPath       string
	NamePath     string
	TypePath     string
	TypeLiteral  string
	AccountPath  string
	// ScopeHeader names a response header carrying comma-separated scopes.
	ScopeHeader string
	// ScopePath is a dot path in the identity document to a scope array or
	// space/comma-separated string.
	ScopePath string
	// ScopeEndpoint, when set, is fetched for ScopeEndpointPath.
	ScopeEndpoint     string
	ScopeEndpointPath string
	PrivilegedScopes  map[string]bool
	// PrivilegedIdentity inspects the identity document and credential.
	PrivilegedIdentity func(doc any, cred detectors.AccessCredential) bool
	Listings           []Listing
	// Notes are always appended to Limitations (documented blind spots).
	Notes    []string
	MaxItems int
}

// Mapper adapts a Spec to detectors.AccessMapper.
type Mapper struct {
	Spec    Spec
	BaseURL string // overrides Spec.BaseURL (tests)
	Client  *http.Client
}

// MapAccess implements detectors.AccessMapper.
func (m Mapper) MapAccess(ctx context.Context, cred detectors.AccessCredential) (*detectors.AccessMap, error) {
	s := m.Spec
	base := firstNonEmpty(cred.Extra["api_endpoint"], cred.Extra["base_url"], m.BaseURL)
	if base == "" {
		if s.RequireEndpoint {
			return nil, fmt.Errorf("%s: credential JSON must include api_endpoint", s.Provider)
		}
		base = s.BaseURL
	}
	base = strings.TrimRight(base, "/")
	if u, err := url.Parse(base); err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && m.BaseURL != "")) || u.Host == "" {
		return nil, fmt.Errorf("%s: api_endpoint must be an https URL", s.Provider)
	}
	hdr, err := s.Auth(cred)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.Provider, err)
	}
	var doc any
	h, err := httpx.GetJSON(ctx, m.Client, base+s.IdentityPath, hdr, &doc)
	if err != nil {
		return nil, fmt.Errorf("%s: identity: %w", s.Provider, err)
	}
	am := detectors.NewAccessMap(s.Provider)
	am.Identity = detectors.AccessIdentity{
		ID:      firstPath(doc, s.IDPath),
		Name:    firstPath(doc, s.NamePath),
		Type:    firstNonEmpty(strings.ToLower(firstPath(doc, s.TypePath)), s.TypeLiteral, "token"),
		Account: firstPath(doc, s.AccountPath),
	}
	if s.ScopeHeader != "" {
		am.Permissions = append(am.Permissions, splitList(h.Get(s.ScopeHeader))...)
	}
	if s.ScopePath != "" {
		am.Permissions = append(am.Permissions, strs(Get(doc, s.ScopePath))...)
	}
	if s.ScopeEndpoint != "" {
		var sd any
		if _, err := httpx.GetJSON(ctx, m.Client, base+s.ScopeEndpoint, hdr, &sd); err != nil {
			am.Limitations = append(am.Limitations, "scopes: "+err.Error())
		} else {
			am.Permissions = append(am.Permissions, strs(Get(sd, s.ScopeEndpointPath))...)
		}
	}
	for _, p := range am.Permissions {
		if s.PrivilegedScopes[p] {
			am.Privileged = true
		}
	}
	if s.PrivilegedIdentity != nil && s.PrivilegedIdentity(doc, cred) {
		am.Privileged = true
	}
	maxItems := s.MaxItems
	if maxItems <= 0 {
		maxItems = DefaultMaxItems
	}
	for _, l := range s.Listings {
		items, truncated, err := m.list(ctx, base, hdr, doc, l, maxItems)
		if err != nil {
			am.Limitations = append(am.Limitations, l.Type+": "+err.Error())
		}
		for _, it := range items {
			res := detectors.AccessResource{Type: l.Type, Name: firstPath(it, l.NamePath)}
			for _, pp := range l.PermPaths {
				res.Permissions = append(res.Permissions, permValues(it, pp)...)
			}
			if l.Privileged != nil && l.Privileged(res.Permissions) {
				am.Privileged = true
			}
			am.Resources = append(am.Resources, res)
		}
		if truncated {
			am.Limitations = append(am.Limitations, fmt.Sprintf("%s listing capped at %d", l.Type, maxItems))
		}
	}
	if len(am.Permissions) == 0 && s.ScopeHeader+s.ScopePath+s.ScopeEndpoint != "" {
		am.Limitations = append(am.Limitations, "token scopes not reported by the provider")
	}
	am.Limitations = append(am.Limitations, s.Notes...)
	return am, nil
}

func (m Mapper) list(ctx context.Context, base string, hdr map[string]string, identity any, l Listing, maxItems int) ([]any, bool, error) {
	if l.Path == "" {
		items := arr(Get(identity, l.ItemsPath))
		if len(items) > maxItems {
			return items[:maxItems], true, nil
		}
		return items, false, nil
	}
	var out []any
	next := base + l.Path
	page := 1
	offset := 0
	for next != "" {
		var doc any
		h, err := httpx.GetJSON(ctx, m.Client, next, hdr, &doc)
		if err != nil {
			return out, false, err
		}
		items := arr(Get(doc, l.ItemsPath))
		out = append(out, items...)
		if len(out) >= maxItems {
			return out[:maxItems], true, nil
		}
		prev := next
		next = ""
		switch l.Paginate {
		case LinkHeader:
			next = httpx.NextLink(h)
		case NextField:
			next = str(Get(doc, l.NextPath))
		case PageParam:
			if len(items) > 0 {
				page++
				next = withParam(base+l.Path, l.PageParam, strconv.Itoa(page))
			}
		case OffsetParam:
			if len(items) > 0 {
				offset += len(items)
				next = withParam(base+l.Path, l.PageParam, strconv.Itoa(offset))
			}
		}
		if next != "" && (!httpx.SameOrigin(base, next) || next == prev) {
			return out, next != prev, nil
		}
	}
	return out, false, nil
}

func withParam(raw, key, val string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set(key, val)
	u.RawQuery = q.Encode()
	return u.String()
}

// Get resolves a dot path ("a.b.0.c") in a decoded JSON value. An empty path
// returns v.
func Get(v any, path string) any {
	if path == "" {
		return v
	}
	for _, seg := range strings.Split(path, ".") {
		switch t := v.(type) {
		case map[string]any:
			v = t[seg]
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(t) {
				return nil
			}
			v = t[i]
		default:
			return nil
		}
	}
	return v
}

func firstPath(v any, paths string) string {
	for _, p := range strings.Split(paths, "|") {
		if s := str(Get(v, p)); s != "" {
			return s
		}
	}
	return ""
}

func permValues(item any, path string) []string {
	switch t := Get(item, path).(type) {
	case bool:
		if t {
			return []string{path[strings.LastIndex(path, ".")+1:]}
		}
	case string:
		if t != "" {
			return []string{t}
		}
	case []any:
		return strs(t)
	}
	return nil
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

func strs(v any) []string {
	switch t := v.(type) {
	case string:
		return splitList(t)
	case []any:
		out := []string{}
		for _, e := range t {
			if s := str(e); s != "" {
				out = append(out, s)
			} else if m, ok := e.(map[string]any); ok {
				if s := firstPath(m, "name|scope|handle|id"); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	case map[string]any:
		out := []string{}
		for k, e := range t {
			if b, ok := e.(bool); ok && b {
				out = append(out, k)
			}
		}
		return out
	}
	return nil
}

func arr(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	return nil
}

func splitList(s string) []string {
	out := []string{}
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
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

// Bearer returns an Authorization: Bearer header builder.
func Bearer(cred detectors.AccessCredential) (map[string]string, error) {
	return map[string]string{"Authorization": "Bearer " + cred.Secret}, nil
}

// Header returns a builder that sends the secret in the named header.
func Header(name, prefix string, extra map[string]string) func(detectors.AccessCredential) (map[string]string, error) {
	return func(cred detectors.AccessCredential) (map[string]string, error) {
		h := map[string]string{name: prefix + cred.Secret}
		for k, v := range extra {
			h[k] = v
		}
		return h, nil
	}
}

// BasicWithExtra uses Extra[userKey] as the username and the secret as the
// password (Atlassian email + API token, Bitbucket username + app password).
// When Extra[userKey] is empty it falls back to Bearer when allowBearer.
func BasicWithExtra(userKey string, allowBearer bool) func(detectors.AccessCredential) (map[string]string, error) {
	return func(cred detectors.AccessCredential) (map[string]string, error) {
		u := cred.Extra[userKey]
		if u == "" {
			if allowBearer {
				return Bearer(cred)
			}
			return nil, errors.New("credential JSON must include " + userKey)
		}
		req, _ := http.NewRequest(http.MethodGet, "https://x", nil)
		req.SetBasicAuth(u, cred.Secret)
		return map[string]string{"Authorization": req.Header.Get("Authorization")}, nil
	}
}

// BasicSecretUser sends the secret as the basic-auth username (Stripe).
func BasicSecretUser(cred detectors.AccessCredential) (map[string]string, error) {
	req, _ := http.NewRequest(http.MethodGet, "https://x", nil)
	req.SetBasicAuth(cred.Secret, "")
	return map[string]string{"Authorization": req.Header.Get("Authorization")}, nil
}
