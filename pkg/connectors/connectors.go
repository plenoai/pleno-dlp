// Package connectors holds SaaS connectors. Each connector lives in a
// single file at pkg/connectors/<name>.go that registers a Connector value
// in init(). A connector is just three function fields — Scan, Verify,
// Revoke — written like an AWS Lambda handler: auth, fetch, emit.
//
// Engine integration: AsSource wraps a registered connector as a
// sources.Source so the engine drives a SaaS scan with the same loop it
// uses for filesystem / git / stdin. Connector authors never see
// jobID / sourceID / concurrency plumbing.
package connectors

import (
	"context"
	"fmt"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// Config is the flat string→string config map a connector receives from
// the CLI / API caller. Connectors validate the keys they care about and
// ignore the rest.
type Config map[string]string

// Get returns cfg[key] or fallback if absent / empty.
func (c Config) Get(key, fallback string) string {
	if v, ok := c[key]; ok && v != "" {
		return v
	}
	return fallback
}

// Emit is the callback a Scan function uses to publish a finding-eligible
// chunk. The framework stamps SourceID / SourceType / SourceName / Verify
// itself; the connector only supplies the bytes and the metadata that
// describe where they came from. Returns ctx.Err() when the consumer is
// cancelled, so loops can short-circuit on a single error check.
type Emit func(data []byte, meta sources.Metadata) error

// Scan walks the configured surface and emits chunks. Per-item errors
// (one 404 in a list of 1000) should be tolerated; the returned error is
// reserved for fatal failures (auth, ctx cancellation).
type Scan func(ctx context.Context, cfg Config, emit Emit) error

// Verify reports whether secret is alive against the provider's
// well-known endpoint (e.g. GitHub GET /user). nil means the connector
// does not implement verify.
type Verify func(ctx context.Context, cfg Config, secret string) (bool, error)

// Revoke invalidates secret server-side. nil means the connector does not
// implement revoke; callers must check before dispatching.
type Revoke func(ctx context.Context, cfg Config, secret string) (detectors.RevokeResult, error)

// Connector is the value each pkg/connectors/<name>.go file registers.
// SourceType is required so AsSource can stamp Chunks; Scan / Verify /
// Revoke are individually optional — set the ones the connector
// implements, leave the rest nil.
type Connector struct {
	SourceType sources.SourceType
	Scan       Scan
	Verify     Verify
	Revoke     Revoke
}

var (
	mu       sync.RWMutex
	registry = map[string]Connector{}
)

// Register installs a connector under name. Panics on duplicate so an
// accidental double-init at process start fails loudly.
func Register(name string, c Connector) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[name]; exists {
		panic("connectors: duplicate registration for " + name)
	}
	registry[name] = c
}

// Get returns the connector registered under name. The zero Connector
// and false are returned when name is unknown.
func Get(name string) (Connector, bool) {
	mu.RLock()
	defer mu.RUnlock()
	c, ok := registry[name]
	return c, ok
}

// Names returns the registered connector names in unspecified order.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	return names
}

// AsSource wraps a registered connector as a sources.Source. The CLI
// builds this once per scan invocation and hands it to the engine just
// like a filesystem / git source.
func AsSource(name string, cfg Config) (sources.Source, error) {
	c, ok := Get(name)
	if !ok {
		return nil, fmt.Errorf("connectors: %q is not registered", name)
	}
	if c.Scan == nil {
		return nil, fmt.Errorf("connectors: %q does not implement scan", name)
	}
	return &sourceAdapter{conn: c, cfg: cfg}, nil
}

type sourceAdapter struct {
	conn       Connector
	cfg        Config
	sourceName string
	sourceID   int64
	verify     bool
}

func (s *sourceAdapter) Type() sources.SourceType { return s.conn.SourceType }

// Init satisfies sources.Source. The framework owns sourceName / sourceID
// / verify; cfg comes from the CLI via AsSource so the legacy `config`
// blob is intentionally ignored — connector inputs flow as a typed
// Config map, not opaque JSON.
func (s *sourceAdapter) Init(_ context.Context, name string, _ int64, sourceID int64, verify bool, _ []byte, _ int) error {
	s.sourceName = name
	s.sourceID = sourceID
	s.verify = verify
	if s.cfg == nil {
		s.cfg = Config{}
	}
	return nil
}

// Chunks runs the connector's Scan, stamping every emitted chunk with
// the framework-owned fields (SourceID / SourceType / SourceName /
// Verify) so the connector author only fills in Data + Metadata.
func (s *sourceAdapter) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	emit := func(data []byte, meta sources.Metadata) error {
		chunk := &sources.Chunk{
			SourceID:       s.sourceID,
			SourceType:     s.conn.SourceType,
			SourceName:     s.sourceName,
			Data:           data,
			SourceMetadata: meta,
			Verify:         s.verify,
		}
		select {
		case ch <- chunk:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.conn.Scan(ctx, s.cfg, emit)
}
