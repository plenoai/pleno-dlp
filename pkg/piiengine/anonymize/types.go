package anonymize

import (
	"errors"
	"io"
	"time"
)

// Config tunes spawn and health behavior. Zero values are usable except Cmd.
type Config struct {
	// Cmd is the argv to spawn. `{PORT}` is substituted before exec.
	Cmd []string

	// Host defaults to loopback and rejects non-loopback values.
	Host string

	// Port is the loopback port. 0 auto-allocates.
	Port int

	// ReadyTimeout caps how long Start waits for /ready.
	ReadyTimeout time.Duration

	// RequestTimeout is the per-Analyze HTTP timeout.
	RequestTimeout time.Duration

	// Language is the default language passed to /api/analyze.
	Language string

	// Stderr optionally receives child stderr.
	Stderr io.Writer
}

type Finding struct {
	// EntityType is pleno-anonymize's entity label.
	EntityType string `json:"entity_type"`
	Start      int    `json:"start"`
	End        int    `json:"end"`
	// Score is the engine's confidence in [0, 1].
	Score float64 `json:"score"`
	// Text is the matched substring.
	Text string `json:"text"`
}

// analyzeRequest is the wire shape posted to /api/analyze.
type analyzeRequest struct {
	Text     string   `json:"text"`
	Language string   `json:"language,omitempty"`
	Entities []string `json:"entities,omitempty"`
}

// Sentinel errors for supervisor failure modes.
var (
	ErrNotStarted    = errors.New("anonymize: supervisor not started")
	ErrSpawnFailed   = errors.New("anonymize: failed to spawn engine")
	ErrReadyTimeout  = errors.New("anonymize: engine /ready timeout")
	ErrEngineExited  = errors.New("anonymize: engine exited before /ready")
	ErrEngineFailed  = errors.New("anonymize: engine returned non-2xx")
	ErrInvalidConfig = errors.New("anonymize: invalid config")
)
