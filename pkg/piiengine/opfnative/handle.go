//go:build opf_native

package opfnative

import "sync/atomic"

// defaultEngine is the process-wide active native engine, published by the
// CLI when --pii-engine=openai-pf-native is selected and read by the
// detector's native adapter. Mirrors openaipf.SetDefault/Default. Exactly
// one PII backend is SetDefault'd per run, so there is no ambiguity.
var defaultEngine atomic.Pointer[Engine]

func SetDefault(e *Engine) { defaultEngine.Store(e) }

func Default() *Engine { return defaultEngine.Load() }
