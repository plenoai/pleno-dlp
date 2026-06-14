// Package stdin reads one chunk from stdin or an injected reader.
package stdin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	name             string
	jobID            int64
	sourceID         int64
	cfg              Config
	reader           io.Reader
	cached           bool
	cachedData       []byte
	cachedTruncated  bool
	hasPreviousState bool
	previousState    *incrementalState
	nextState        *incrementalState
}

func (s *Source) Type() sources.SourceType { return sources.SourceStdin }

// SetReader overrides the input reader.
func (s *Source) SetReader(r io.Reader) {
	s.reader = r
	s.cached = false
	s.cachedData = nil
	s.cachedTruncated = false
}

func (s *Source) Init(_ context.Context, name string, jobID, sourceID int64, _ bool, config []byte, _ int) error {
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
	s.cfg = cfg
	s.cached = false
	s.cachedData = nil
	s.cachedTruncated = false
	s.hasPreviousState = false
	s.previousState = nil
	s.nextState = nil
	return nil
}

var errStdinTruncated = errors.New("stdin: input exceeded max_bytes; trailing data was discarded")

func IsTruncationError(err error) bool { return errors.Is(err, errStdinTruncated) }

func (s *Source) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, truncated, err := s.readInput()
	if err != nil {
		return err
	}
	current := incrementalState{Version: 1, Hash: hashData(data), Label: s.cfg.Label}
	s.nextState = &current
	if s.hasPreviousState && s.previousState != nil && *s.previousState == current {
		if truncated {
			return errStdinTruncated
		}
		return nil
	}

	chunk := &sources.Chunk{
		SourceID:   s.sourceID,
		SourceType: sources.SourceStdin,
		SourceName: s.name,
		Data:       data,
		SourceMetadata: sources.Metadata{
			Stdin: &sources.StdinMeta{Label: s.cfg.Label},
		},
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

func (s *Source) ResourceFingerprint(_ context.Context) (string, error) {
	data, truncated, err := s.readInput()
	if err != nil {
		return "", err
	}
	state := incrementalState{Version: 1, Hash: hashData(data), Label: s.cfg.Label}
	s.nextState = &state
	if truncated {
		return state.Hash + ":truncated", nil
	}
	return state.Hash, nil
}

type incrementalState struct {
	Version int    `json:"version"`
	Hash    string `json:"hash"`
	Label   string `json:"label"`
}

func (s *Source) SetIncrementalState(previous json.RawMessage) error {
	s.hasPreviousState = false
	s.previousState = nil
	if len(previous) == 0 {
		return nil
	}
	var state incrementalState
	if err := json.Unmarshal(previous, &state); err != nil {
		return fmt.Errorf("stdin: invalid incremental state: %w", err)
	}
	s.previousState = &state
	s.hasPreviousState = true
	return nil
}

func (s *Source) IncrementalState() json.RawMessage {
	if s.nextState == nil {
		return nil
	}
	data, err := json.Marshal(s.nextState)
	if err != nil {
		return nil
	}
	return data
}

func (s *Source) readInput() ([]byte, bool, error) {
	if s.cached {
		return s.cachedData, s.cachedTruncated, nil
	}
	r := s.reader
	if r == nil {
		r = os.Stdin
	}
	limited := io.LimitReader(r, s.cfg.MaxBytes)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, false, fmt.Errorf("stdin: read: %w", err)
	}
	truncated := false
	overflow := make([]byte, 1)
	if n, _ := r.Read(overflow); n > 0 {
		truncated = true
	}
	s.cached = true
	s.cachedData = data
	s.cachedTruncated = truncated
	return data, truncated, nil
}

func hashData(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// compile-time interface check
var _ sources.Source = (*Source)(nil)
var _ sources.ResourceFingerprinter = (*Source)(nil)
var _ sources.IncrementalStateSource = (*Source)(nil)
