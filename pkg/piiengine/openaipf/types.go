package openaipf

import (
	"errors"
	"io"
	"time"
)

const DefaultReadyTimeout = 300 * time.Second

// Config tunes spawn and health behavior. Zero values are usable except Cmd.
type Config struct {
	// Cmd is the argv to spawn. `{PORT}` is substituted before exec.
	Cmd []string

	// Host defaults to loopback and rejects non-loopback values.
	Host string

	// Port is the loopback port. 0 auto-allocates.
	Port int

	// Device is the inference device hint: auto, cpu, cuda, or mps.
	Device string

	// ReadyTimeout caps how long Start waits for /ready.
	ReadyTimeout time.Duration

	// RequestTimeout is the per-Analyze HTTP timeout.
	RequestTimeout time.Duration

	// Stderr optionally receives child stderr.
	Stderr io.Writer
}

type Finding struct {
	// EntityType is the aggregated opf category.
	EntityType string `json:"entity_type"`
	// BIOESTag is the raw token tag.
	BIOESTag string `json:"bioes_tag,omitempty"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
	// Score is opf's confidence in [0, 1].
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
	ErrNotStarted    = errors.New("openaipf: supervisor not started")
	ErrSpawnFailed   = errors.New("openaipf: failed to spawn engine")
	ErrReadyTimeout  = errors.New("openaipf: engine /ready timeout")
	ErrEngineExited  = errors.New("openaipf: engine exited before /ready")
	ErrEngineFailed  = errors.New("openaipf: engine returned non-2xx")
	ErrInvalidConfig = errors.New("openaipf: invalid config")
)
