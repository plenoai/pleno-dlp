//go:build opf_native

package openaipf

import (
	"context"

	opfn "github.com/plenoai/pleno-dlp/pkg/piiengine/opfnative"
)

// In an opf_native build the in-process privacy-filter.cpp engine takes
// precedence over the subprocess supervisor whenever it is the active
// backend. Exactly one PII backend is SetDefault'd per run, so preferring
// opfnative.Default() and falling back to the previous productionAnalyzer
// is unambiguous — the fallback preserves the subprocess path for a native
// build that was started with --pii-engine=openai-pf.
func init() {
	prev := fetchAnalyzer
	fetchAnalyzer = func() Analyzer {
		if e := opfn.Default(); e != nil {
			return nativeAdapter{e: e}
		}
		return prev()
	}
}

// nativeAdapter bridges opfnative.Engine to the detector's local Analyzer /
// Finding types, mirroring supervisorAdapter so FromData stays
// backend-agnostic.
type nativeAdapter struct{ e *opfn.Engine }

func (nativeAdapter) engineImpl() string { return "native" }

func (a nativeAdapter) Analyze(ctx context.Context, text string) ([]Finding, error) {
	fs, err := a.e.Analyze(ctx, text)
	if err != nil {
		return nil, err
	}
	if len(fs) == 0 {
		return nil, nil
	}
	out := make([]Finding, len(fs))
	for i, f := range fs {
		out[i] = Finding{
			EntityType: f.EntityType,
			BIOESTag:   f.BIOESTag,
			Start:      f.Start,
			End:        f.End,
			Score:      f.Score,
			Text:       f.Text,
		}
	}
	return out, nil
}
