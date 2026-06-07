// Package stdin reads one chunk from stdin or an injected reader.
package stdin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const defaultMaxBytes int64 = 64 * 1024 * 1024

const defaultLabel = "<stdin>"

func init() {
	sources.Register(sources.SourceStdin, func() sources.Source { return &Source{} })
}

type Config struct {
	Label    string `json:"label,omitempty"`
	MaxBytes int64  `json:"max_bytes,omitempty"`
}

type Source struct {
	name     string
	jobID    int64
	sourceID int64
	verify   bool
	cfg      Config
	reader   io.Reader
}

func (s *Source) Type() sources.SourceType { return sources.SourceStdin }

// SetReader overrides the input reader.
func (s *Source) SetReader(r io.Reader) { s.reader = r }

func (s *Source) Init(_ context.Context, name string, jobID, sourceID int64, verify bool, config []byte, _ int) error {
	var cfg Config
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return fmt.Errorf("stdin: invalid config json: %w", err)
		}
	}
	if cfg.Label == "" {
		cfg.Label = defaultLabel
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaultMaxBytes
	}
	s.name = name
	s.jobID = jobID
	s.sourceID = sourceID
	s.verify = verify
	s.cfg = cfg
	return nil
}

var errStdinTruncated = errors.New("stdin: input exceeded max_bytes; trailing data was discarded")

func IsTruncationError(err error) bool { return errors.Is(err, errStdinTruncated) }

func (s *Source) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r := s.reader
	if r == nil {
		r = os.Stdin
	}
	limited := io.LimitReader(r, s.cfg.MaxBytes)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("stdin: read: %w", err)
	}
	truncated := false
	overflow := make([]byte, 1)
	if n, _ := r.Read(overflow); n > 0 {
		truncated = true
	}

	chunk := &sources.Chunk{
		SourceID:   s.sourceID,
		SourceType: sources.SourceStdin,
		SourceName: s.name,
		Data:       data,
		SourceMetadata: sources.Metadata{
			Stdin: &sources.StdinMeta{Label: s.cfg.Label},
		},
		Verify: s.verify,
	}
	select {
	case ch <- chunk:
	case <-ctx.Done():
		return ctx.Err()
	}
	if truncated {
		return errStdinTruncated
	}
	return nil
}

// compile-time interface check
var _ sources.Source = (*Source)(nil)
