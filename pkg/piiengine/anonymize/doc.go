// Package anonymize manages the lifecycle of an external pleno-anonymize
// HTTP server bound to a loopback port and exposes a thin Analyze client.
//
// The supervisor exists because pleno-anonymize is a Python application
// (spaCy + Presidio + ja_ner_ja) with no Go bindings and a multi-second
// cold start. Per ADR-0001 we amortize that cost by spawning the server
// once at scan start, calling POST /api/analyze per chunk, and shutting
// it down at scan end. The spawn argv is supplied by the caller via
// Config.Cmd (with a {PORT} placeholder that the supervisor substitutes);
// this supervisor never assumes a binary on $PATH. Per ADR-0003 the
// recommended default argv is `pleno-dlp pii-server --port {PORT}`,
// which itself shells out to `uvx` to run the upstream Python server —
// no Docker is involved (ADR-0003 supersedes ADR-0002 on that point).
//
// Invariants enforced by this package:
//
//   - Bind address defaults to 127.0.0.1; supplying a public interface
//     is rejected at New() time. A DLP tool must never relay scanned
//     text to a public listener.
//   - Start blocks on /ready (which lazy-loads the NER models) rather
//     than /health (which reports liveness only). Cold-start in our
//     CI is around 6–9s.
//   - Analyze is safe for concurrent goroutines. The HTTP client is
//     concurrent-safe by stdlib contract; lifecycle state is guarded
//     by a mutex so Stop-during-Analyze cannot race the http.Client
//     shutdown.
//   - Stop is idempotent and tolerates being called from a defer
//     even when Start failed. Spawn failures return typed errors so
//     callers can downgrade gracefully (warn + skip PII, continue
//     secret scan).
//
// The detector half of this feature lives in pkg/detectors/anonymize;
// it retrieves the singleton Supervisor via the package-level handle
// (SetDefault / Default) wired by the engine entrypoint when
// --pii-engine=anonymize.
package anonymize
