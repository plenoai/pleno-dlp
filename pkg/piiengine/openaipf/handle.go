package openaipf

import "sync/atomic"

// defaultSupervisor is the package-level singleton handed off from the
// engine wiring layer to the detector. atomic.Pointer guarantees safe
// publication: the engine's lifecycle goroutine writes once at scan
// start (and once at scan end to reset to nil), while every scan
// worker goroutine reads via Default() to dispatch FromData.
//
// A typed atomic pointer instead of a sync.RWMutex because the read
// path is the hot loop: every chunk that contains a PII keyword does
// one Default() call. atomic.Pointer.Load is a single uncontended
// load; an RWMutex would add an atomic inc/dec pair and a memory
// barrier per read. The openaipf and anonymize handles live in
// separate packages on purpose (ADR-0004 §4) so each detector reads
// only its own engine's singleton — never both.
var defaultSupervisor atomic.Pointer[Supervisor]

// SetDefault publishes s as the package-level Supervisor. Callers
// (the engine wiring layer) call SetDefault(supervisor) after Start
// succeeds and SetDefault(nil) inside the deferred shutdown path.
//
// The detector treats Default() == nil as "PII engine off, return
// no findings", so it is critical that SetDefault(nil) runs before
// Stop blocks on the child's exit — otherwise an in-flight Analyze
// call could land on a half-killed process. The engine wiring layer
// is responsible for that ordering; this package only guarantees
// that the publish itself is race-free.
func SetDefault(s *Supervisor) {
	defaultSupervisor.Store(s)
}

// Default returns the package-level Supervisor, or nil if no
// supervisor is active.
//
// The detector calls Default() at the top of FromData. A nil return
// means the engine is off (--pii-engine=off / --pii-engine=anonymize,
// or spawn failed and the engine layer downgraded to skip-and-warn)
// and the detector should return (nil, nil) without any work.
func Default() *Supervisor {
	return defaultSupervisor.Load()
}
