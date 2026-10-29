// Package redactiontest applies the display contract to detector fixtures.
package redactiontest

import (
	"bytes"
	"context"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"io"
	"testing"
)

type scanner interface {
	FromData(context.Context, bool, []byte) ([]detectors.Result, error)
}

// FromData checks both secrets without changing the detector's returned results.
func FromData(t testing.TB, detector scanner, ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	t.Helper()
	results, err := detector.FromData(ctx, verify, data)
	check(t, results)
	return results, err
}

type readerScanner interface {
	FromReader(context.Context, bool, io.ReaderAt, int64) ([]detectors.Result, error)
}

// FromReader checks the same contract for reader-based detector fixtures.
func FromReader(t testing.TB, detector readerScanner, ctx context.Context, verify bool, input io.ReaderAt, size int64) ([]detectors.Result, error) {
	t.Helper()
	results, err := detector.FromReader(ctx, verify, input, size)
	check(t, results)
	return results, err
}

func check(t testing.TB, results []detectors.Result) {
	t.Helper()
	for index, result := range results {
		if len(result.Raw) > 0 && bytes.Contains([]byte(result.Redacted), result.Raw) {
			t.Errorf("result %d Redacted contains complete Raw", index)
		}
		if len(result.RawV2) > 0 && bytes.Contains([]byte(result.Redacted), result.RawV2) {
			t.Errorf("result %d Redacted contains complete RawV2", index)
		}
	}
}
