// Package feedback stores and sends user-authored feedback reports.
//
// A feedback report is an opt-in, user-initiated message plus minimal build
// context. Unlike crash telemetry, sending is never enabled implicitly: the
// operator types the message and confirms the send. Every report that leaves
// the machine is also written to a local spool first, so there is always a
// local copy of exactly what was sent. See docs/feedback.md.
package feedback
