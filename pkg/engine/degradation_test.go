package engine

import (
	"errors"
	"testing"
)

func TestPartitionDegradedErrorsAggregatesJoinedCoverage(t *testing.T) {
	firstCause := errors.New("first")
	secondCause := errors.New("second")
	joined := errors.Join(
		&DegradedError{
			Total:  1,
			Counts: map[FailureKind]int{FailureSource: 1},
			Failures: []ScanFailure{
				{Kind: FailureSource, Source: "source-a", Err: firstCause},
			},
		},
		&DegradedError{
			Total:  2,
			Counts: map[FailureKind]int{FailureArchive: 2},
			Failures: []ScanFailure{
				{Kind: FailureArchive, Source: "archive-a", Err: secondCause},
			},
		},
	)

	coverage, residual := PartitionDegradedErrors(joined)
	if residual != nil {
		t.Fatalf("residual = %v, want nil", residual)
	}
	if coverage == nil || coverage.Total != 3 ||
		coverage.Counts[FailureSource] != 1 || coverage.Counts[FailureArchive] != 2 {
		t.Fatalf("coverage = %#v, want aggregated totals", coverage)
	}
	if len(coverage.Failures) != 2 || !errors.Is(coverage, firstCause) || !errors.Is(coverage, secondCause) {
		t.Fatalf("coverage examples/causes were not retained: %#v", coverage)
	}
}

func TestPartitionDegradedErrorsKeepsFatalResidual(t *testing.T) {
	fatalErr := errors.New("fatal")
	coverage, residual := PartitionDegradedErrors(errors.Join(
		fatalErr,
		&DegradedError{Total: 1, Counts: map[FailureKind]int{FailureDetector: 1}},
	))
	if coverage == nil || coverage.Total != 1 {
		t.Fatalf("coverage = %#v, want detector degradation", coverage)
	}
	if !errors.Is(residual, fatalErr) {
		t.Fatalf("residual = %v, want fatal error", residual)
	}
}
