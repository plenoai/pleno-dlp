// Package stdin is a Source that reads a single chunk from os.Stdin (or any
// io.Reader, for tests) and emits it once. It exists so users can pipe
// arbitrary text — `git diff`, `kubectl get secret -o yaml`, ad-hoc shell
// output — through the scanner without first writing it to a tempfile.
//
// Limits: there is no streaming chunking. Stdin is buffered into memory
// up to MaxBytes, which defaults to 64 MiB. Inputs larger than that are
// truncated (truncation is reported via the returned error so CI scripts
// can choose to fail). Binary input is not pre-filtered; the engine's
// downstream byte-classification still applies.
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

// defaultMaxBytes caps how much of stdin we buffer. 64 MiB is the same
// ballpark as the filesystem source's per-file size cap and large enough
// to cover any realistic `git diff` or k8s manifest dump.
const defaultMaxBytes int64 = 64 * 1024 * 1024

// defaultLabel is the StdinMeta.Label used when the user didn't pass one.
// We use "<stdin>" — angle brackets borrowed from the Unix convention for
// pseudo-paths so output formatters render something obvious.
const defaultLabel = "<stdin>"

func init() {
	sources.Register(sources.SourceStdin, func() sources.Source { return &Source{} })
}

// Config is the JSON shape Init expects. Label rides through to
// StdinMeta.Label so users can label the input (e.g. "git-diff") and have
// that show up in JSON / SARIF / table output. MaxBytes overrides the
// defaultMaxBytes cap for unusual workloads.
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
	// reader is os.Stdin in production, swapped in tests so we don't have
	// to fork a subprocess. Nil means "use os.Stdin" — set explicitly with
	// SetReader before Chunks runs.
	reader io.Reader
}

func (s *Source) Type() sources.SourceType { return sources.SourceStdin }

// SetReader lets tests inject a deterministic input. Production code
// leaves this nil; Chunks falls back to os.Stdin in that case.
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

// errStdinTruncated signals that input exceeded MaxBytes and was clipped.
// Returned alongside the emitted chunk so the caller can decide whether
// truncation is fatal — most CI runs prefer to fail loudly.
var errStdinTruncated = errors.New("stdin: input exceeded max_bytes; trailing data was discarded")

// IsTruncationError reports whether err is the truncation sentinel.
// Exposed so callers (notably the CLI layer) can distinguish "scan
// finished but input was clipped" from a fatal read error.
func IsTruncationError(err error) bool { return errors.Is(err, errStdinTruncated) }

func (s *Source) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r := s.reader
	if r == nil {
		r = os.Stdin
	}
	// LimitReader caps the buffered bytes; the +1 byte sniff afterwards
	// tells us whether the input would have continued past the cap.
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
