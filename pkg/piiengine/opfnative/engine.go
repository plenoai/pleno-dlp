//go:build opf_native

package opfnative

// #include <stdlib.h>
// #include "pf.h"
import "C"

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"unsafe"
)

// Engine holds a single pf_ctx. pf_classify's thread-safety on a shared
// ctx is not guaranteed by the ABI, so Analyze is serialized by mu. One
// GGUF load amortizes over the whole scan.
type Engine struct {
	mu        sync.Mutex
	ctx       *C.pf_ctx
	threshold C.float
}

// New loads the GGUF at cfg.ModelPath via pf_load. The returned Engine owns
// the C context until Close.
func New(cfg Config) (*Engine, error) {
	if cfg.ModelPath == "" {
		return nil, ErrEmptyModelPath
	}
	threshold := cfg.Threshold
	if threshold <= 0 {
		threshold = DefaultThreshold
	}

	cpath := C.CString(cfg.ModelPath)
	defer C.free(unsafe.Pointer(cpath))

	var cdevice *C.char
	if dev := resolveDevice(cfg.Device); dev != "" {
		cdevice = C.CString(dev)
		defer C.free(unsafe.Pointer(cdevice))
	}

	ctx := C.pf_load(cpath, cdevice, 0)
	if ctx == nil {
		// pf_load returns NULL on failure and pf_last_error is keyed on a
		// live ctx, so no message is retrievable here.
		return nil, fmt.Errorf("%w: %s", ErrLoadFailed, cfg.ModelPath)
	}
	return &Engine{ctx: ctx, threshold: C.float(threshold)}, nil
}

// Analyze classifies text and returns one Finding per entity. Byte offsets
// from libpf index the original UTF-8 text directly, so the matched
// substring is a plain byte slice of text.
func (e *Engine) Analyze(ctx context.Context, text string) ([]Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(text) == 0 {
		return nil, nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ctx == nil {
		return nil, ErrClosed
	}

	ctext := C.CString(text)
	defer C.free(unsafe.Pointer(ctext))

	var ents *C.pf_entity
	var n C.size_t
	rc := C.pf_classify(e.ctx, ctext, C.size_t(len(text)), e.threshold, &ents, &n)
	if rc != 0 {
		return nil, fmt.Errorf("%w: %s", ErrClassify, C.GoString(C.pf_last_error(e.ctx)))
	}
	if n == 0 || ents == nil {
		return nil, nil
	}
	defer C.pf_entities_free(ents, n)

	slice := unsafe.Slice(ents, int(n))
	out := make([]Finding, int(n))
	for i, ent := range slice {
		out[i] = Finding{
			EntityType: C.GoString(ent.label),
			Start:      int(ent.start),
			End:        int(ent.end),
			Score:      float64(ent.score),
			Text:       substr(text, int(ent.start), int(ent.end)),
		}
	}
	return out, nil
}

// Close frees the C context. Safe to call more than once.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ctx == nil {
		return nil
	}
	C.pf_free(e.ctx)
	e.ctx = nil
	return nil
}

// resolveDevice maps the CLI device hint onto pf_load's vocabulary.
func resolveDevice(d string) string {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "", "auto":
		return platformAutoDevice
	case "mps":
		return "gpu"
	default:
		return d
	}
}

// substr slices text by byte offsets, returning "" on any out-of-range or
// inverted span rather than panicking on a malformed offset from libpf.
func substr(text string, start, end int) string {
	if start < 0 || end > len(text) || start > end {
		return ""
	}
	return text[start:end]
}
