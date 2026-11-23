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
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

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
	// Query sends a GraphQL POST {"query": Query} to Path (or the spec's
	// IdentityPath when Path is empty) instead of a GET.
	Query string
	// Body sends a JSON POST with the expanded template (see Expand).
	Body string
}

// Exchange trades the credential for a short-lived bearer token before any
// other request (OAuth client credentials, IBM IAM API-key grant).
type Exchange struct {
	Path string // POST target, relative to the base URL or absolute
	// Form is an x-www-form-urlencoded template; JSON a JSON body template.
	Form, JSON string
	// BasicUser/BasicPass, when set, are templates for HTTP basic auth.
	BasicUser, BasicPass string
	TokenPath            string // default "access_token"
	ScopePath            string // optional granted-scope field
	// KeepAuth keeps Spec.Auth headers beside the exchanged bearer token.
	KeepAuth bool
}

// Activity reads the provider-reported last use of the credential.
type Activity struct {
	Path string // template; relative or absolute
	// LinkPath is a dot path in the identity document to a same-origin
	// relative link used instead of Path (Terraform auth-token link).
	LinkPath     string
	LastUsedPath string
	Service      string
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
	// Base computes the base URL from the credential (per-tenant hosts).
	Base func(cred detectors.AccessCredential) (string, error)
	// Exchange runs before identity resolution.
	Exchange *Exchange
	// IdentityQuery makes the identity request a GraphQL POST.
	IdentityQuery string
	// IdentityBody makes the identity request a JSON POST (template).
	IdentityBody string
	// IDTemplate fills Identity.ID from the credential when the provider
	// has no identity field (or IdentityPath is empty: no identity call).
	IDTemplate string
	Activity   *Activity
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
	base := firstNonEmpty(m.BaseURL, cred.Extra["api_endpoint"], cred.Extra["base_url"])
	if base == "" && s.Base != nil {
		b, err := s.Base(cred)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.Provider, err)
		}
		base = b
	}
	if base == "" {
		if s.RequireEndpoint {
			return nil, fmt.Errorf("%s: credential JSON must include api_endpoint", s.Provider)
		}
		base = s.BaseURL
	}
	base = strings.TrimRight(base, "/")
	if u, err := url.Parse(base); err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && m.BaseURL != "")) || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("%s: api_endpoint must be an https URL", s.Provider)
	}
	hdr := map[string]string{}
	if s.Auth != nil {
		h, err := s.Auth(cred)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.Provider, err)
		}
		hdr = h
	}
	am := detectors.NewAccessMap(s.Provider)
	if s.Exchange != nil {
		tok, scopes, err := m.exchange(ctx, base, hdr, cred)
		if err != nil {
			return nil, fmt.Errorf("%s: token exchange: %w", s.Provider, err)
		}
		if !s.Exchange.KeepAuth {
			hdr = map[string]string{}
		}
		hdr["Authorization"] = "Bearer " + tok
		am.Permissions = append(am.Permissions, scopes...)
	}
	var doc any
	var h http.Header
	if s.IdentityPath != "" {
		var err error
		h, err = m.request(ctx, m.abs(base, Expand(s.IdentityPath, cred, "", queryEnc)), hdr, s.IdentityQuery, Expand(s.IdentityBody, cred, "", jsonEnc), &doc)
		if err != nil {
			return nil, fmt.Errorf("%s: identity: %w", s.Provider, err)
		}
	}
	am.Identity = detectors.AccessIdentity{
		ID:      firstNonEmpty(firstPath(doc, s.IDPath), Expand(s.IDTemplate, cred, "", rawEnc)),
		Name:    firstPath(doc, s.NamePath),
		Type:    firstNonEmpty(strings.ToLower(firstPath(doc, s.TypePath)), s.TypeLiteral, "token"),
		Account: firstPath(doc, s.AccountPath),
	}
	if s.ScopeHeader != "" && h != nil {
		am.Permissions = append(am.Permissions, splitList(h.Get(s.ScopeHeader))...)
	}
	if s.ScopePath != "" {
		am.Permissions = append(am.Permissions, strs(Get(doc, s.ScopePath))...)
	}
	if s.ScopeEndpoint != "" {
		var sd any
		if _, err := httpx.GetJSON(ctx, m.Client, m.abs(base, Expand(s.ScopeEndpoint, cred, am.Identity.ID, queryEnc)), hdr, &sd); err != nil {
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
		items, truncated, err := m.list(ctx, base, hdr, doc, cred, am.Identity.ID, l, maxItems)
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
	if s.Activity != nil {
		m.activity(ctx, base, hdr, doc, cred, am)
	}
	if len(am.Permissions) == 0 && s.ScopeHeader+s.ScopePath+s.ScopeEndpoint != "" {
		am.Limitations = append(am.Limitations, "token scopes not reported by the provider")
	}
	am.Limitations = append(am.Limitations, s.Notes...)
	return am, nil
}

// abs resolves p against base. An absolute spec URL keeps its own host in
// production; a test BaseURL override replaces its origin.
func (m Mapper) abs(base, p string) string {
	if strings.HasPrefix(p, "https://") {
		if m.BaseURL == "" {
			return p
		}
		u, err := url.Parse(p)
		if err != nil {
			return p
		}
		return strings.TrimRight(m.BaseURL, "/") + u.RequestURI()
	}
	return base + p
}

func (m Mapper) request(ctx context.Context, target string, hdr map[string]string, query, body string, dst any) (http.Header, error) {
	if query == "" && body == "" {
		return httpx.GetJSON(ctx, m.Client, target, hdr, dst)
	}
	if query != "" {
		b, _ := json.Marshal(map[string]string{"query": query})
		body = string(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	var doc any
	h, err := httpx.Do(httpx.Client(m.Client), req, &doc)
	if err != nil {
		return h, err
	}
	if query != "" {
		if errs := arr(Get(doc, "errors")); len(errs) > 0 {
			msg := firstPath(errs[0], "message")
			if len(msg) > 200 {
				msg = msg[:200]
			}
			return h, fmt.Errorf("graphql error: %s", msg)
		}
	}
	if p, ok := dst.(*any); ok {
		*p = doc
	}
	return h, nil
}

func (m Mapper) exchange(ctx context.Context, base string, hdr map[string]string, cred detectors.AccessCredential) (string, []string, error) {
	x := m.Spec.Exchange
	var body io.Reader
	ctype := ""
	switch {
	case x.JSON != "":
		body, ctype = strings.NewReader(Expand(x.JSON, cred, "", jsonEnc)), "application/json"
	default:
		body, ctype = strings.NewReader(Expand(x.Form, cred, "", url.QueryEscape)), "application/x-www-form-urlencoded"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.abs(base, x.Path), body)
	if err != nil {
		return "", nil, err
	}
	if x.KeepAuth {
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("Accept", "application/json")
	if x.BasicUser != "" {
		req.SetBasicAuth(Expand(x.BasicUser, cred, "", rawEnc), Expand(x.BasicPass, cred, "", rawEnc))
	}
	var doc any
	if _, err := httpx.Do(httpx.Client(m.Client), req, &doc); err != nil {
		return "", nil, err
	}
	tok := str(Get(doc, firstNonEmpty(x.TokenPath, "access_token")))
	if tok == "" {
		return "", nil, errors.New("no access token in response")
	}
	var scopes []string
	if x.ScopePath != "" {
		scopes = strs(Get(doc, x.ScopePath))
	}
	return tok, scopes, nil
}

func (m Mapper) activity(ctx context.Context, base string, hdr map[string]string, identity any, cred detectors.AccessCredential, am *detectors.AccessMap) {
	a := m.Spec.Activity
	target := ""
	if a.LinkPath != "" {
		link := str(Get(identity, a.LinkPath))
		if !strings.HasPrefix(link, "/") || strings.HasPrefix(link, "//") || strings.Contains(link, "..") {
			return
		}
		target = base + link
	} else {
		if strings.Contains(a.Path, "{id}") && am.Identity.ID == "" {
			return
		}
		target = m.abs(base, Expand(a.Path, cred, am.Identity.ID, queryEnc))
	}
	var doc any
	if _, err := httpx.GetJSON(ctx, m.Client, target, hdr, &doc); err != nil {
		am.Limitations = append(am.Limitations, "activity: "+err.Error())
		return
	}
	if ts := NormalizeTime(Get(doc, a.LastUsedPath)); ts != "" {
		am.Activity = &detectors.AccessActivity{LastUsed: ts, Service: a.Service}
	}
}

// NormalizeTime converts an RFC 3339 string or a Unix-seconds number into
// an RFC 3339 UTC timestamp; anything else yields "".
func NormalizeTime(v any) string {
	switch t := v.(type) {
	case float64:
		if t > 0 {
			return time.Unix(int64(t), 0).UTC().Format(time.RFC3339)
		}
	case string:
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000-0700", "2006-01-02T15:04-0700", "2006-01-02T15:04:05-0700"} {
			if ts, err := time.Parse(layout, t); err == nil {
				return ts.UTC().Format(time.RFC3339)
			}
		}
	}
	return ""
}

var placeholder = regexp.MustCompile(`\{(secret|secondary|id|extra\.[a-z_]+)\}`)

func rawEnc(s string) string { return s }

func jsonEnc(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

func queryEnc(s string) string { return url.QueryEscape(s) }

// safeID keeps provider identifiers to a conservative character set before
// they are substituted into request paths or queries (SOQL, REST paths).
func safeID(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || r == '.' || r == ':' || r == '@' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return r
		}
		return -1
	}, s)
}

// Expand substitutes {secret}, {secondary}, {extra.<key>} and {id} (the
// resolved identity ID, restricted by safeID) in t, encoding each value
// with enc.
func Expand(t string, cred detectors.AccessCredential, id string, enc func(string) string) string {
	if t == "" {
		return ""
	}
	return placeholder.ReplaceAllStringFunc(t, func(p string) string {
		k := p[1 : len(p)-1]
		switch {
		case k == "secret":
			return enc(cred.Secret)
		case k == "secondary":
			return enc(cred.Secondary)
		case k == "id":
			return enc(safeID(id))
		default:
			return enc(cred.Extra[strings.TrimPrefix(k, "extra.")])
		}
	})
}

func (m Mapper) list(ctx context.Context, base string, hdr map[string]string, identity any, cred detectors.AccessCredential, id string, l Listing, maxItems int) ([]any, bool, error) {
	if l.Path == "" && l.Query == "" {
		items := arr(Get(identity, l.ItemsPath))
		if len(items) > maxItems {
			return items[:maxItems], true, nil
		}
		return items, false, nil
	}
	var out []any
	first := m.abs(base, Expand(firstNonEmpty(l.Path, m.Spec.IdentityPath), cred, id, queryEnc))
	next := first
	page := 1
	offset := 0
	for next != "" {
		var doc any
		h, err := m.request(ctx, next, hdr, l.Query, Expand(l.Body, cred, id, jsonEnc), &doc)
		if err != nil {
			return out, false, err
		}
		items := arr(Get(doc, l.ItemsPath))
		if m, ok := doc.(map[string]any); ok && l.ItemsPath == "" {
			items = []any{m}
		}
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
			next = resolve(prev, str(Get(doc, l.NextPath)))
		case PageParam:
			if len(items) > 0 {
				page++
				next = withParam(first, l.PageParam, strconv.Itoa(page))
			}
		case OffsetParam:
			if len(items) > 0 {
				offset += len(items)
				next = withParam(first, l.PageParam, strconv.Itoa(offset))
			}
		}
		if next != "" && (!httpx.SameOrigin(first, next) || next == prev) {
			return out, next != prev, nil
		}
	}
	return out, false, nil
}

func resolve(from, ref string) string {
	if ref == "" {
		return ""
	}
	b, err1 := url.Parse(from)
	r, err2 := url.Parse(ref)
	if err1 != nil || err2 != nil {
		return ""
	}
	return b.ResolveReference(r).String()
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
