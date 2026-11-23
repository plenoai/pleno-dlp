// Package blastradius resolves verified credentials into identity,
// permissions, and reachable resources (detectors.AccessMap). It owns the
// provider registry used by `scan --blast-radius` and the standalone
// `pleno-dlp blast-radius <provider>` command.
package blastradius

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/blastradius/aws"
	"github.com/plenoai/pleno-dlp/pkg/blastradius/gcp"
	"github.com/plenoai/pleno-dlp/pkg/blastradius/github"
	"github.com/plenoai/pleno-dlp/pkg/blastradius/gitlab"
	"github.com/plenoai/pleno-dlp/pkg/blastradius/slack"
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

// Registry is the built-in provider set. Tests replace mappers with
// httptest-backed instances via NewRegistry.
type Registry struct {
	byName     map[string]Provider
	byDetector map[detectors.DetectorType]Provider
}

// Default returns the registry wired to production endpoints.
func Default() *Registry {
	return NewRegistry(
		Provider{Name: "aws", Mapper: aws.Mapper{}, Detectors: []detectors.DetectorType{detectors.AWS}},
		Provider{Name: "gcp", Mapper: gcp.Mapper{}, Detectors: []detectors.DetectorType{detectors.GCPServiceAccount}},
		Provider{Name: "github", Mapper: github.Mapper{}, Detectors: []detectors.DetectorType{detectors.GitHub}},
		Provider{Name: "gitlab", Mapper: gitlab.Mapper{}, Detectors: []detectors.DetectorType{detectors.GitLab}},
		Provider{Name: "slack", Mapper: slack.Mapper{}, Detectors: []detectors.DetectorType{detectors.SlackBotToken}},
	)
}

// NewRegistry builds a registry from explicit providers.
func NewRegistry(ps ...Provider) *Registry {
	r := &Registry{byName: map[string]Provider{}, byDetector: map[detectors.DetectorType]Provider{}}
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
	}
	return detectors.AccessCredential{Secret: string(res.Raw)}
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
	return p.Mapper.MapAccess(ctx, CredentialFromResult(res))
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
	if provider == "aws" {
		id, sk, ok := strings.Cut(trimmed, ":")
		if !ok {
			return detectors.AccessCredential{}, fmt.Errorf("aws credential must be JSON or access_key_id:secret_access_key")
		}
		return detectors.AccessCredential{Secret: id, Secondary: sk}, nil
	}
	return detectors.AccessCredential{Secret: trimmed}, nil
}
