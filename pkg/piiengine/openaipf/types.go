package openaipf

import (
	"errors"
	"io"
	"time"
)

// DefaultReadyTimeout is the default budget for /ready to flip green.
//
// Cold-path is HuggingFace checkpoint download (1.5B params, multi-GB)
// + transformers import + first forward pass that JIT-compiles kernels.
// 60s (the anonymize default) is insufficient — empirical first-run on
// a network-fast machine is 90–180s; a cold uv cache + slow link can
// easily exceed 200s. 300s gives the cold path enough budget while
// staying well below a CI runner's default job timeout. ADR-0004 §8.
const DefaultReadyTimeout = 300 * time.Second

// Config tunes spawn + health behavior. Zero values are usable defaults
// except Cmd, which is required.
//
// Config mirrors anonymize.Config one-to-one with two intentional
// deltas — Device (opf-only knob) and a longer ReadyTimeout default —
// so the engine wiring layer can branch by name only, not by shape.
// Every knob lives here so unit tests can drive the supervisor with a
// httptest.Server without touching the real Python engine.
type Config struct {
	// Cmd is the argv to spawn. The literal token "{PORT}" is
	// substituted with the chosen ephemeral port before exec; this
	// lets the same Config drive the documented
	// `pleno-dlp openai-pf-server --port {PORT}` self-invocation, a
	// direct `uvx` recipe, or a local `python -m openaipf_server`
	// without per-form branching in the supervisor. Required: empty
	// Cmd makes New return an error so callers must either supply a
	// recipe or skip starting the supervisor entirely.
	Cmd []string

	// Host pins the bind address. Defaults to "127.0.0.1" — we never
	// bind a public interface for a DLP tool (ADR-0001 hard rule).
	// Anything other than a loopback literal ("127.0.0.1", "::1",
	// "localhost") is rejected at New() time.
	Host string

	// Port is the loopback port. 0 = auto-allocate via net.Listen on
	// ":0" then close immediately and pass the port via {PORT}. The
	// listen-and-close pattern is a tiny TOCTOU but acceptable for
	// our use case; Start's /ready poll surfaces genuine bind failure
	// regardless of root cause.
	Port int

	// Device is the inference device hint: "auto" | "cpu" | "cuda" |
	// "mps". The supervisor itself never introspects device state;
	// the Python wrapper consumes this through its own --device flag
	// and reports the chosen device on /ready. Empty = let the
	// engine pick (equivalent to "auto"). Wired by the CLI to the
	// subcommand argv, not by this package — Device on Config is
	// retained for parity with anonymize.Language (operator-facing
	// hint surfaced via supervisor) and for future use should opf
	// gain a per-request device override.
	Device string

	// ReadyTimeout caps how long Start waits for /ready to return 200.
	// Defaults to DefaultReadyTimeout (300s). The CLI exposes
	// --pii-engine-ready-timeout for operators on a cold uv cache or
	// slow network — first-run downloads multi-GB weights from
	// HuggingFace.
	ReadyTimeout time.Duration

	// RequestTimeout is the per-Analyze HTTP timeout. Defaults to 10s.
	// Long enough that a single chunk against a warm engine completes
	// comfortably; short enough that a stalled engine doesn't wedge
	// the whole scan.
	RequestTimeout time.Duration

	// Stderr (optional) receives the child process's stderr so engine
	// logs can surface HF download progress, spawn failures, and OOM
	// chatter. nil = discard. The supervisor pipes the child's
	// stderr line-by-line to this writer; it does not alter or buffer
	// beyond os.Pipe's own kernel buffer.
	Stderr io.Writer
}

// Finding is the per-entity result returned by /api/analyze.
//
// The FastAPI wrapper does the BIOES → span aggregation server-side
// (BIOES state-machine logic in Go would duplicate work opf already
// does in Python), so each Finding here is one resolved span — not a
// raw token tag. BIOESTag is carried through for span debugging only;
// the canonical category for routing is EntityType.
//
// JSON tags match the wrapper's response shape verbatim so the
// supervisor can decode without a translation layer. The detector
// half of the feature maps EntityType to ExtraData["pii_kind"] per
// ADR-0004 §6.
type Finding struct {
	// EntityType is the opf category string after BIOES aggregation,
	// e.g. "private_emails", "private_persons", "secrets". The detector
	// translates this into the wire-stable pii_kind via mapping.go.
	EntityType string `json:"entity_type"`
	// BIOESTag is the raw opf token tag (e.g. "E-private_emails").
	// Optional; aids span debugging when a multi-token entity collapses
	// to a single Finding. Empty when the wrapper omits it.
	BIOESTag string `json:"bioes_tag,omitempty"`
	// Start is the byte offset in the input where the entity begins.
	Start int `json:"start"`
	// End is the byte offset just past the entity (Go-style slice).
	End int `json:"end"`
	// Score is opf's confidence in [0, 1]. Below ~0.5 is typically
	// noise but the supervisor returns everything; the detector
	// decides on a threshold.
	Score float64 `json:"score"`
	// Text is the substring matched. Convenience field — the detector
	// can rebuild it from Start/End and the original input.
	Text string `json:"text"`
}

// analyzeRequest is the wire shape posted to /api/analyze. Defined
// here (not in client.go) so it sits next to Finding and the JSON
// contract is reviewable in one place.
//
// language and entities are reserved fields the wrapper accepts but
// the Go side does not currently set. They are listed here so a
// future caller can populate them without changing the wire format
// of in-flight scans.
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
	ErrNotStarted = errors.New("openaipf: supervisor not started")
	// ErrSpawnFailed wraps the underlying os/exec error when the
	// child process refuses to start (binary missing, exec format
	// error, etc.).
	ErrSpawnFailed = errors.New("openaipf: failed to spawn engine")
	// ErrReadyTimeout means /ready did not return 200 within
	// Config.ReadyTimeout. The child is killed before this returns.
	ErrReadyTimeout = errors.New("openaipf: engine /ready timeout")
	// ErrEngineExited means the child process exited before /ready
	// ever returned 200. Surfaced as a separate sentinel so callers
	// can distinguish a slow start from a crashed start — otherwise
	// every misconfigured spawn would burn the full ReadyTimeout.
	ErrEngineExited = errors.New("openaipf: engine exited before /ready")
	// ErrEngineFailed wraps a non-2xx response from /api/analyze.
	// The HTTP body (truncated) is included in the wrapped message
	// for log triage.
	ErrEngineFailed = errors.New("openaipf: engine returned non-2xx")
	// ErrInvalidConfig is returned by New for impossible Configs:
	// empty Cmd, public bind host, etc. Surfaced at construction
	// time so misconfigurations fail before any side effect.
	ErrInvalidConfig = errors.New("openaipf: invalid config")
)
