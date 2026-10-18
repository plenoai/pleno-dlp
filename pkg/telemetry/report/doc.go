// Package report builds, redacts, validates, spools, and sends anonymized
// pleno-dlp reports: crash reports captured by pkg/telemetry/crash, and
// feedback or false-positive reports an operator submits explicitly.
//
// Every report shares one allowlisted wire shape (Schema). Free text passes
// through Redactor before it is stored or sent; see docs/telemetry.md.
package report
