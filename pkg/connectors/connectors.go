// Package connectors holds SaaS connectors and adapts them to sources.Source.
package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	configKeyIncrementalPreviousState = "_pleno_incremental_previous_state"
	configKeyIncrementalNextState     = "_pleno_incremental_next_state"
	configKeyIncrementalPartialSafe   = "_pleno_incremental_partial_safe"
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
	flush      sources.IncrementalFlushFunc
}

// incrementalFlushCtxKey は connector が ctx 経由で flush callback を
// 取り出すための key。 sourceAdapter.Chunks が inject、 connector 側は
// IncrementalFlushFromContext で取り出す。
type incrementalFlushCtxKey struct{}

// IncrementalFlushFromContext は sourceAdapter が ctx に inject した flush
// callback を返す。 connector が per-unit (per-repo / per-page) 完了の
// たびに呼び、 引数に最新の source state を渡す。 callback が無ければ nil。
func IncrementalFlushFromContext(ctx context.Context) sources.IncrementalFlushFunc {
	v, _ := ctx.Value(incrementalFlushCtxKey{}).(sources.IncrementalFlushFunc)
	return v
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
		}
		select {
		case ch <- chunk:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if s.flush != nil {
		ctx = context.WithValue(ctx, incrementalFlushCtxKey{}, s.flush)
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

func (s *sourceAdapter) SetIncrementalState(previous json.RawMessage) error {
	if s.cfg == nil {
		s.cfg = Config{}
	}
	delete(s.cfg, configKeyIncrementalNextState)
	delete(s.cfg, configKeyIncrementalPartialSafe)
	if len(previous) > 0 {
		s.cfg[configKeyIncrementalPreviousState] = string(previous)
	} else {
		delete(s.cfg, configKeyIncrementalPreviousState)
	}
	return nil
}

func (s *sourceAdapter) PartialIncrementalStateSafe() bool {
	return s.cfg != nil && parseBool(s.cfg[configKeyIncrementalPartialSafe])
}

var _ sources.PartialIncrementalStateSource = (*sourceAdapter)(nil)

func (s *sourceAdapter) IncrementalState() json.RawMessage {
	if s.cfg != nil {
		if next := s.cfg[configKeyIncrementalNextState]; next != "" {
			return json.RawMessage(next)
		}
	}
	return nil
}

var _ sources.IncrementalStateSource = (*sourceAdapter)(nil)

// SetIncrementalFlush は cmd 層が「per-unit 完了時に partial state を
// 受け取りたい」ときに closure を渡す setter。 sourceAdapter は受け取った
// closure を Chunks(ctx) で ctx に inject し、 connector がそれを取り出
// して呼ぶ (connectors.IncrementalFlushFromContext)。
func (s *sourceAdapter) SetIncrementalFlush(f sources.IncrementalFlushFunc) {
	s.flush = f
}

var _ sources.IncrementalFlushSource = (*sourceAdapter)(nil)
