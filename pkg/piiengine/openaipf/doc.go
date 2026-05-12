// Package openaipf manages the lifecycle of an external openai/privacy-filter
// (opf) HTTP server bound to a loopback port and exposes a thin Analyze
// client.
//
// opf is a 1.5B-parameter MoE PII classifier (Apache 2.0, Python-only).
// Upstream ships only a CLI and a Python API — there is no upstream HTTP
// server. Per ADR-0004 we ship a minimal FastAPI wrapper at
// python/openaipf-server/ inside this repo; uvx materializes it on first
// run from the same git URL pleno-dlp itself ships from. This supervisor
// is the Go-side lifecycle peer of that wrapper: spawn → /ready gate →
// POST /api/analyze per chunk → graceful shutdown at scan end.
//
// openaipf is a sibling of pkg/piiengine/anonymize, not a replacement.
// The two-package shape (supervisor here, detector at pkg/detectors/openaipf)
// matches what ADR-0002 established for anonymize so a future third engine
// slots in identically. Wire contracts (Config, Finding, sentinel errors)
// are intentionally close to anonymize's; the deltas (Device flag, 300s
// ReadyTimeout, no Language default, BIOES tag passthrough) reflect opf's
// model shape, not a stylistic divergence.
//
// Invariants enforced by this package:
//
//   - Bind address defaults to 127.0.0.1; a non-loopback Host is rejected
//     at New() time (ADR-0001 hard rule — a DLP tool must never relay
//     scanned text to a public listener).
//   - Start blocks on /ready, which the FastAPI wrapper only flips after
//     opf's checkpoint download + first forward pass complete. Cold-path
//     for a multi-GB HuggingFace download on a fresh runner is multi-minute;
//     DefaultReadyTimeout is 300s and the CLI exposes
//     --pii-engine-ready-timeout for operators on a cold cache.
//   - Analyze is safe for concurrent goroutines. http.Client is concurrent-
//     safe by stdlib contract; lifecycle state is guarded by a mutex so
//     Stop-during-Analyze cannot race the http client shutdown.
//   - Stop is idempotent and tolerates being called from a defer even
//     when Start failed. Spawn failures return typed errors so callers
//     can downgrade gracefully (warn + skip PII, continue secret scan).
//
// The detector half of this feature lives in pkg/detectors/openaipf;
// it retrieves the singleton Supervisor via the package-level handle
// (SetDefault / Default) wired by the engine entrypoint when
// --pii-engine=openai-pf.
package openaipf
