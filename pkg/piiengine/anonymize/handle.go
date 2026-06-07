package anonymize

import "sync/atomic"

var defaultSupervisor atomic.Pointer[Supervisor]

func SetDefault(s *Supervisor) {
	defaultSupervisor.Store(s)
}

func Default() *Supervisor {
	return defaultSupervisor.Load()
}
