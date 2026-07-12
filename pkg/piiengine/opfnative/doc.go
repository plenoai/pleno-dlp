// Package opfnative is the in-process privacy-filter.cpp PII engine, gated
// by build tag opf_native (ADR-0005). It loads the openai/privacy-filter
// GGUF once via cgo (pf_load), classifies chunks in-process (pf_classify),
// and frees it at scan end (pf_free).
//
// This file carries no build tag so the default CGO_ENABLED=0 pure-Go
// build sees a valid (empty) package instead of "build constraints exclude
// all Go files"; every implementation unit is tagged opf_native.
package opfnative
