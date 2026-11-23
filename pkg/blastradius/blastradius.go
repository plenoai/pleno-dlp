// Package blastradius resolves verified credentials into identity,
// permissions, and reachable resources (detectors.AccessMap). It owns the
// provider registry used by `scan --blast-radius` and the standalone
// `pleno-dlp blast-radius <provider>` command.
package blastradius

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/blastradius/alibaba"
	"github.com/plenoai/pleno-dlp/pkg/blastradius/aws"
	"github.com/plenoai/pleno-dlp/pkg/blastradius/azure"
	"github.com/plenoai/pleno-dlp/pkg/blastradius/gcp"
	"github.com/plenoai/pleno-dlp/pkg/blastradius/github"
	"github.com/plenoai/pleno-dlp/pkg/blastradius/gitlab"
	"github.com/plenoai/pleno-dlp/pkg/blastradius/slack"
	"github.com/plenoai/pleno-dlp/pkg/blastradius/spec"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// ExtraDataKey is the Result.ExtraData key carrying the JSON-encoded
// AccessMap produced during `scan --blast-radius`.
const ExtraDataKey = "blast_radius_map"

// Provider couples a provider name with its mapper and the detector types
// whose findings it can map.
type Provider struct {
	Name      string
	Mapper    detectors.AccessMapper
	Detectors []detectors.DetectorType
}

// DefaultConcurrency bounds simultaneous MapResult calls per registry so a
// large scan with many verified findings does not fan out unbounded
// provider requests.
const DefaultConcurrency = 4

// Registry is the built-in provider set. Tests replace mappers with
// httptest-backed instances via NewRegistry. A Registry memoizes MapResult
// per credential for its lifetime (one scan run), so duplicate findings of
// the same secret are mapped once.
type Registry struct {
	byName     map[string]Provider
	byDetector map[detectors.DetectorType]Provider

	sem   chan struct{}
	mu    sync.Mutex
	cache map[[32]byte]*cacheEntry
}

type cacheEntry struct {
	done chan struct{}
	am   *detectors.AccessMap
	err  error
}

// Default returns the registry wired to production endpoints.
func Default() *Registry {
	ps := []Provider{
		{Name: "aws", Mapper: aws.Mapper{}, Detectors: []detectors.DetectorType{detectors.AWS}},
		{Name: "gcp", Mapper: gcp.Mapper{}, Detectors: []detectors.DetectorType{detectors.GCPServiceAccount}},
		{Name: "github", Mapper: github.Mapper{}, Detectors: []detectors.DetectorType{detectors.GitHub}},
		{Name: "gitlab", Mapper: gitlab.Mapper{}, Detectors: []detectors.DetectorType{detectors.GitLab}},
		{Name: "slack", Mapper: slack.Mapper{}, Detectors: []detectors.DetectorType{detectors.SlackBotToken}},
		{Name: "azure", Mapper: azure.ServicePrincipalMapper{}, Detectors: []detectors.DetectorType{detectors.AzureAD, detectors.AzureApp}},
		{Name: "azure-storage", Mapper: azure.StorageKeyMapper{}, Detectors: []detectors.DetectorType{detectors.AzureStorageKey}},
		{Name: "alibaba", Mapper: alibaba.Mapper{}, Detectors: []detectors.DetectorType{detectors.AlibabaCloud}},
	}
	for _, s := range spec.All {
		ps = append(ps, Provider{Name: s.Spec.Provider, Mapper: spec.Mapper{Spec: s.Spec}, Detectors: s.Detectors})
	}
	return NewRegistry(ps...)
}

// NewRegistry builds a registry from explicit providers.
func NewRegistry(ps ...Provider) *Registry {
	r := &Registry{
		byName:     map[string]Provider{},
		byDetector: map[detectors.DetectorType]Provider{},
		sem:        make(chan struct{}, DefaultConcurrency),
		cache:      map[[32]byte]*cacheEntry{},
	}
	for _, p := range ps {
		r.byName[p.Name] = p
		for _, d := range p.Detectors {
			r.byDetector[d] = p
		}
	}
	return r
}

// Names lists registered provider names, sorted.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.byName))
	for n := range r.byName {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Lookup returns the provider registered under name (case-insensitive).
func (r *Registry) Lookup(name string) (Provider, bool) {
	p, ok := r.byName[strings.ToLower(name)]
	return p, ok
}

// Supports reports whether findings of detector type t can be mapped.
func (r *Registry) Supports(t detectors.DetectorType) bool {
	_, ok := r.byDetector[t]
	return ok
}

// CredentialFromResult derives the mapper input from a detector result.
func CredentialFromResult(res detectors.Result) detectors.AccessCredential {
	switch res.DetectorType {
	case detectors.AWS:
		return detectors.AccessCredential{Secret: string(res.Raw), Secondary: string(res.RawV2)}
	case detectors.GCPServiceAccount:
		return detectors.AccessCredential{Secret: string(res.RawV2)}
	case detectors.AlibabaCloud:
		return detectors.AccessCredential{Secret: string(res.Raw), Secondary: string(res.RawV2)}
	}
	c := detectors.AccessCredential{Secret: string(res.Raw)}
	// Context the detector extracted beside the secret (Entra tenant/client
	// ids, storage account name, self-hosted endpoint).
	for _, k := range []string{"tenant_id", "client_id", "account", "api_endpoint"} {
		if v := res.ExtraData[k]; v != "" {
			if c.Extra == nil {
				c.Extra = map[string]string{}
			}
			c.Extra[k] = v
		}
	}
	return c
}

// MapResult maps a verified detector result. It returns (nil, nil) when the
// result is unverified or its detector has no registered mapper.
func (r *Registry) MapResult(ctx context.Context, res detectors.Result) (*detectors.AccessMap, error) {
	if !res.Verified {
		return nil, nil
	}
	p, ok := r.byDetector[res.DetectorType]
	if !ok {
		return nil, nil
	}
	return r.mapCached(ctx, p, CredentialFromResult(res))
}

// SetConcurrency changes the MapResult concurrency bound (minimum 1). Call it
// before mapping starts.
func (r *Registry) SetConcurrency(n int) {
	if n < 1 {
		n = 1
	}
	r.sem = make(chan struct{}, n)
}

func cacheKey(provider string, c detectors.AccessCredential) [32]byte {
	h := sha256.New()
	keys := make([]string, 0, len(c.Extra))
	for k := range c.Extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(h, "%d:%s%d:%s%d:%s", len(provider), provider, len(c.Secret), c.Secret, len(c.Secondary), c.Secondary)
	for _, k := range keys {
		fmt.Fprintf(h, "%d:%s%d:%s", len(k), k, len(c.Extra[k]), c.Extra[k])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// mapCached deduplicates concurrent and repeated mappings of one credential
// and bounds in-flight provider calls. Only the hash of the credential is
// retained as the key. Errors caused by the caller's context are not cached.
func (r *Registry) mapCached(ctx context.Context, p Provider, cred detectors.AccessCredential) (*detectors.AccessMap, error) {
	key := cacheKey(p.Name, cred)
	r.mu.Lock()
	if e, ok := r.cache[key]; ok {
		r.mu.Unlock()
		select {
		case <-e.done:
			return e.am, e.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	e := &cacheEntry{done: make(chan struct{})}
	r.cache[key] = e
	r.mu.Unlock()

	select {
	case r.sem <- struct{}{}:
		e.am, e.err = p.Mapper.MapAccess(ctx, cred)
		<-r.sem
	case <-ctx.Done():
		e.err = ctx.Err()
	}
	if e.err != nil && ctx.Err() != nil {
		r.mu.Lock()
		delete(r.cache, key)
		r.mu.Unlock()
	}
	close(e.done)
	return e.am, e.err
}

// ParseCredentialFile decodes a standalone credential artifact. A JSON object
// with a "token" (or AWS "access_key_id"/"secret_access_key") field is read as
// structured input; GCP accepts the service-account key file verbatim; any
// other content is treated as a bare token.
func ParseCredentialFile(provider string, data []byte) (detectors.AccessCredential, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return detectors.AccessCredential{}, fmt.Errorf("empty credential input")
	}
	if provider == "gcp" {
		return detectors.AccessCredential{Secret: trimmed}, nil
	}
	if strings.HasPrefix(trimmed, "{") {
		var f map[string]string
		if err := json.Unmarshal([]byte(trimmed), &f); err != nil {
			return detectors.AccessCredential{}, fmt.Errorf("credential JSON: %w", err)
		}
		c := detectors.AccessCredential{Extra: map[string]string{}}
		for k, v := range f {
			switch k {
			case "token", "access_key_id":
				c.Secret = v
			case "secret_access_key":
				c.Secondary = v
			default:
				c.Extra[k] = v
			}
		}
		if c.Secret == "" {
			return c, fmt.Errorf("credential JSON missing token/access_key_id")
		}
		return c, nil
	}
	if provider == "aws" || provider == "alibaba" {
		id, sk, ok := strings.Cut(trimmed, ":")
		if !ok {
			return detectors.AccessCredential{}, fmt.Errorf("%s credential must be JSON or access_key_id:secret_access_key", provider)
		}
		return detectors.AccessCredential{Secret: id, Secondary: sk}, nil
	}
	return detectors.AccessCredential{Secret: trimmed}, nil
}
