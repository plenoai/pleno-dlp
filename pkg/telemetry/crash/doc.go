// Package crash builds, redacts, spools, and (when the operator has opted
// in) sends anonymized crash reports for pleno-dlp.
//
// The package never prompts and never sends by default. Every report is
// spooled locally so an operator can inspect it before choosing to send.
// Reports carry only build metadata, the subcommand path, flag names, and a
// redacted panic message and stack; see docs/telemetry.md.
package crash
