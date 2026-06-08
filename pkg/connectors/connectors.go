// Package connectors holds SaaS connectors and adapts them to sources.Source.
package connectors

import (
	"context"
	"fmt"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type Config map[string]string

func (c Config) Get(key, fallback string) string {
	if v, ok := c[key]; ok && v != "" {
		return v
	}
	return fallback
}

type Emit func(data []byte, meta sources.Metadata) error

type Scan func(ctx context.Context, cfg Config, emit Emit) error

type Verify func(ctx context.Context, cfg Config, secret string) (bool, error)

type Revoke func(ctx context.Context, cfg Config, secret string) (detectors.RevokeResult, error)

type Fingerprint func(ctx context.Context, cfg Config) (string, error)

type Connector struct {
	SourceType  sources.SourceType
	Scan        Scan
	Verify      Verify
	Revoke      Revoke
	Fingerprint Fingerprint
}

var (
	mu       sync.RWMutex
	registry = map[string]Connector{}
)

func Register(name string, c Connector) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[name]; exists {
		panic("connectors: duplicate registration for " + name)
	}
	registry[name] = c
}

func Get(name string) (Connector, bool) {
	mu.RLock()
	defer mu.RUnlock()
	c, ok := registry[name]
	return c, ok
}

func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	return names
}

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

func (s *sourceAdapter) Init(_ context.Context, name string, _ int64, sourceID int64, verify bool, _ []byte, _ int) error {
	s.sourceName = name
	s.sourceID = sourceID
	s.verify = verify
	if s.cfg == nil {
		s.cfg = Config{}
	}
	return nil
}

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

func (s *sourceAdapter) ResourceFingerprint(ctx context.Context) (string, error) {
	if s.conn.Fingerprint == nil {
		return "", fmt.Errorf("connectors: %s source does not implement fingerprint", s.conn.SourceType.String())
	}
	return s.conn.Fingerprint(ctx, s.cfg)
}

var _ sources.ResourceFingerprinter = (*sourceAdapter)(nil)
