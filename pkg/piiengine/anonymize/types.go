package anonymize

import (
	"errors"
	"io"
	"time"
)

// Config tunes spawn + health behavior. Zero values are usable defaults
// except Cmd, which is required.
//
// Config is the single dependency-injection seam for the supervisor:
// every knob a caller might want to tune (which binary to spawn,
// which loopback port, how long to wait for /ready, where to forward
// stderr) lives here so unit tests can drive the supervisor with a
// httptest.Server without touching the real Python engine.
type Config struct {
	// Cmd is the argv to spawn. The literal token "{PORT}" is
	// substituted with the chosen ephemeral port before exec; this
	// lets the same Config drive `docker run`, `uvx`, or a local
	// `uv run` without per-form branching in the supervisor.
	// Required: empty Cmd makes New return an error so callers must
	// either supply a recipe or skip starting the supervisor entirely.
	Cmd []string

	// Host pins the bind address. Defaults to "127.0.0.1" — we never
	// bind a public interface for a DLP tool (ADR-0001 hard rule).
	// Anything other than a loopback literal ("127.0.0.1", "::1",
	// "localhost") is rejected at New() time.
	Host string

	// Port is the loopback port. 0 = auto-allocate via net.Listen on
	// ":0" then close immediately and pass the port via {PORT}. Note
	// the listen-and-close pattern races against another local
	// process grabbing the port between close and exec; for our use
	// case (single-developer scan, ephemeral) this is acceptable and
	// the Start /ready poll covers genuine bind failure.
	Port int

	// ReadyTimeout caps how long Start waits for /ready to return 200.
	// Defaults to 60s — spaCy + ja_ner_ja cold start is multi-second
	// on first invocation; Docker image pull on first run can be much
	// longer than that, so the CLI exposes --pii-engine-ready-timeout
	// for operators who haven't pre-pulled the image.
	ReadyTimeout time.Duration

	// RequestTimeout is the per-Analyze HTTP timeout. Defaults to 10s.
	// Long enough that a single chunk against a warm engine completes
	// comfortably; short enough that a stalled engine doesn't wedge
	// the whole scan.
	RequestTimeout time.Duration

	// Language is the default language passed to /api/analyze when
	// the caller does not supply one. Empty = let the engine pick.
	// "auto" is a sentinel core-engineer translates to empty before
	// reaching the wire.
	Language string

	// Stderr (optional) receives the child process's stderr so engine
	// logs can surface spawn failures and model-load chatter. nil =
	// discard. The supervisor pipes the child's stderr line-by-line
	// to this writer; it does not alter or buffer beyond os.Pipe's
	// own kernel buffer.
	Stderr io.Writer
}

// Finding is the per-entity result returned by /api/analyze.
//
// The JSON tags match pleno-anonymize's response shape verbatim so
// the supervisor can decode without a translation layer. The
// detector half of the feature maps EntityType to ExtraData["pii_kind"]
// and the offset pair to a redaction span.
type Finding struct {
	// EntityType is pleno-anonymize's entity label, e.g. "PERSON",
	// "EMAIL_ADDRESS", "JP_MY_NUMBER", "PHONE_NUMBER".
	EntityType string `json:"entity_type"`
	// Start is the byte offset in the input where the entity begins.
	Start int `json:"start"`
	// End is the byte offset just past the entity (Go-style slice).
	End int `json:"end"`
	// Score is the engine's confidence in [0, 1]. Below ~0.5 is
	// typically noise but the supervisor returns everything; the
	// detector decides on a threshold.
	Score float64 `json:"score"`
	// Text is the substring matched. Convenience field — the
	// detector can rebuild it from Start/End and the original input.
	Text string `json:"text"`
}

// analyzeRequest is the wire shape posted to /api/analyze. Defined
// here (not in client.go) so it sits next to Finding and the JSON
// contract is reviewable in one place.
type analyzeRequest struct {
	Text     string   `json:"text"`
	Language string   `json:"language,omitempty"`
	Entities []string `json:"entities,omitempty"`
}

// Sentinel errors so callers can branch on failure mode without
// string matching. The engine wiring layer downgrades ErrSpawnFailed
// and ErrReadyTimeout to a single warning-and-skip; ErrEngineFailed
// is per-request and is logged by the detector.
var (
	// ErrNotStarted is returned by Analyze when the supervisor has
	// never been Started or has already been Stopped.
	ErrNotStarted = errors.New("anonymize: supervisor not started")
	// ErrSpawnFailed wraps the underlying os/exec error when the
	// child process refuses to start (binary missing, exec format
	// error, etc.).
	ErrSpawnFailed = errors.New("anonymize: failed to spawn engine")
	// ErrReadyTimeout means /ready did not return 200 within
	// Config.ReadyTimeout. The child is killed before this returns.
	ErrReadyTimeout = errors.New("anonymize: engine /ready timeout")
	// ErrEngineFailed wraps a non-2xx response from /api/analyze.
	// The HTTP body (truncated) is included in the wrapped message
	// for log triage.
	ErrEngineFailed = errors.New("anonymize: engine returned non-2xx")
	// ErrInvalidConfig is returned by New for impossible Configs:
	// empty Cmd, public bind host, etc. Surfaced at construction
	// time so misconfigurations fail before any side effect.
	ErrInvalidConfig = errors.New("anonymize: invalid config")
)
