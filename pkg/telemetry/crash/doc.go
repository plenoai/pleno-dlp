// Package crash captures pleno-dlp crashes (a supervising parent process
// and an in-process recover) and hands them to pkg/telemetry/report, which
// redacts, spools, and, only after the operator has opted in, sends them.
//
// The package never prompts and never sends by default; see
// docs/telemetry.md.
package crash
