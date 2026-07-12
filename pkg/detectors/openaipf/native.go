//go:build opf_native

package openaipf

import (
	"context"

	opfn "github.com/plenoai/pleno-dlp/pkg/piiengine/opfnative"
)

func init() {
	fetchAnalyzer = func() Analyzer {
		if e := opfn.Default(); e != nil {
			return nativeAdapter{e: e}
		}
		return nil
	}
}

// nativeAdapter bridges opfnative.Engine to the detector's local Analyzer /
// Finding types, mirroring supervisorAdapter so FromData stays
// backend-agnostic.
type nativeAdapter struct{ e *opfn.Engine }

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
