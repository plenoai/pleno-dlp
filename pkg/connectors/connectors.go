// Package connectors defines the SaaSConnector contract every
// pkg/connectors/<provider>/ implementation satisfies, plus a small
// registry so the CLI can address connectors by name (`pleno-dlp scan
// github`, `pleno-dlp verify slack`, `pleno-dlp revoke gitlab`).
//
// A SaaSConnector is a sources.Source — it walks a provider's documents
// and emits *sources.Chunk into the engine just like filesystem/git/stdin
// — and additionally advertises connector-level metadata (auth modes,
// capability flags) plus optional Verifier / Revoker behaviour against
// the configured token. Composing Source rather than inventing a
// parallel iterator keeps the engine ignorant of the source's origin
// (filesystem vs SaaS) and lets every existing dedup / archive / decoder
// pipeline pass through unchanged.
//
// Concrete implementations live under pkg/connectors/<provider>/ and
// self-register via init(); none of them ship with this file (architect
// only owns the contract, not the providers).
package connectors

import (
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// Capability is a bitmask describing what surfaces a connector
// implements beyond Source iteration. Bits are stable across releases;
// new bits are appended, never reordered.
type Capability uint32

const (
	// CapSource means the connector emits *sources.Chunk via the
	// Source contract. Every SaaSConnector sets this bit by virtue
	// of embedding sources.Source — it is listed explicitly so the
	// registry can surface "what does this connector do?" answers
	// without reflection.
	CapSource Capability = 1 << iota
	// CapVerify means the connector implements detectors.Verifier
	// against the user-supplied token (typically a single
	// well-known endpoint such as GitHub's GET /user).
	CapVerify
	// CapRevoke means the connector implements detectors.Revoker
	// against the user-supplied token. Most providers do NOT
	// expose a revocation API — only set this when the connector
	// has a working Revoke implementation (issue #73).
	CapRevoke
)

// Has reports whether c includes every bit in want.
func (c Capability) Has(want Capability) bool { return c&want == want }

// AuthMode enumerates the credential-shape families a connector accepts.
// A connector typically supports several (e.g. PAT plus OAuth plus app
// installation token). Values are stable; new modes append.
type AuthMode int

const (
	// AuthUnknown is the zero value and indicates the connector did
	// not classify its auth surface — treat as a configuration bug.
	AuthUnknown AuthMode = iota
	// AuthPAT — long-lived personal access token (`Authorization:
	// Bearer <pat>` or provider-specific header).
	AuthPAT
	// AuthBearer — short-lived OAuth bearer token, treated by the
	// transport identically to AuthPAT but distinct in audit logs.
	AuthBearer
	// AuthBasic — HTTP Basic with username + secret (Bitbucket app
	// password, Atlassian email + API token).
	AuthBasic
	// AuthOAuth — full OAuth 2.0 dance (workspace install,
	// refresh-token rotation handled inside the connector).
	AuthOAuth
	// AuthAppInstallation — GitHub App / similar installation
	// tokens minted by JWT exchange against the provider.
	AuthAppInstallation
)

// Descriptor is the static, connector-level metadata the registry and
// the CLI introspect. It does NOT carry secrets — credential material
// flows through sources.Source.Init's `config []byte` blob.
type Descriptor struct {
	// Name is the registry key and CLI sub-command (`github`,
	// `gitlab`, `slack`, ...). Lowercase, no spaces.
	Name string
	// SourceType is the wire-stable sources.SourceType this
	// connector emits via *sources.Chunk. Used by output formatters
	// to dispatch on Chunk.SourceMetadata.
	SourceType sources.SourceType
	// AuthModes lists every credential shape the connector accepts.
	// First entry is the documented default for `--token` flag wiring.
	AuthModes []AuthMode
	// Capabilities is a bitmask of CapSource / CapVerify /
	// CapRevoke. Listing connectors with `--capability revoke` reads
	// this field directly.
	Capabilities Capability
}

// SaaSConnector is the contract every pkg/connectors/<provider>/
// implementation satisfies. It composes sources.Source so the engine
// drives a SaaS scan with the exact same loop it uses for filesystem /
// git / stdin sources — Init parses provider-specific config (token,
// org/repo selectors, api-base override), Chunks streams *sources.Chunk
// into the engine, and Type returns the wire-stable sources.SourceType.
//
// Implementations OPTIONALLY also satisfy detectors.Verifier (verify
// the configured token against a well-known endpoint) and
// detectors.Revoker (revoke the configured token via a provider
// revocation API). Whether a given connector implements those
// optional contracts is reflected in Descriptor.Capabilities so the
// CLI can refuse `pleno-dlp revoke <name>` early when CapRevoke is
// unset, without reaching for a runtime type assertion failure.
type SaaSConnector interface {
	sources.Source
	// Descriptor returns the static metadata for this connector.
	// Safe to call before Init; MUST NOT depend on connector state.
	Descriptor() Descriptor
}

// Verifier is re-exported from pkg/detectors so connector packages
// only need a single `pkg/connectors` import to declare both their
// SaaSConnector implementation and their Verify method.
type Verifier = detectors.Verifier

// Revoker is re-exported from pkg/detectors. Same rationale as
// Verifier — keep connector author imports tight.
type Revoker = detectors.Revoker

// RevokeResult is re-exported from pkg/detectors.
type RevokeResult = detectors.RevokeResult

// Factory constructs a fresh, uninitialised SaaSConnector. Init must be
// called before Chunks / Verify / Revoke. Factories MUST be cheap —
// they run during init() registration and per `pleno-dlp <subcommand>
// <name>` invocation.
type Factory func() SaaSConnector

var (
	mu       sync.RWMutex
	registry = map[string]Factory{}
)

// Register installs a Factory under name. Panics on duplicate
// registration so an accidental double-init at process start fails
// loudly instead of silently shadowing.
func Register(name string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[name]; exists {
		panic("connectors: duplicate registration for " + name)
	}
	registry[name] = f
}

// New returns a fresh SaaSConnector for name, or nil if no connector
// is registered under that name.
func New(name string) SaaSConnector {
	mu.RLock()
	defer mu.RUnlock()
	if f, ok := registry[name]; ok {
		return f()
	}
	return nil
}

// Names returns the registered connector names in unspecified order.
// Callers that need stable ordering must sort the result themselves.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	return names
}
