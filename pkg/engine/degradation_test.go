package engine

import (
	"errors"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/archive"
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

func TestScanFailureSeveritySeparatesPolicySkipsFromGaps(t *testing.T) {
	corrupt := &redactedArchiveCoverageError{cause: &archive.PartialError{Kind: "corrupt-archive", Entry: "a.zip", Err: errors.New("bad")}}
	cases := []struct {
		failure ScanFailure
		want    CoverageSeverity
	}{
		{ScanFailure{Kind: FailureArchive, Err: corrupt}, SeverityPolicySkip},
		{ScanFailure{Kind: FailureArchive, Err: &archive.PartialError{Kind: "max-files", Err: errors.New("cap")}}, SeverityPolicySkip},
		{ScanFailure{Kind: FailureArchive, Err: errors.New("read failed")}, SeverityGap},
		{ScanFailure{Kind: FailureSource, Err: corrupt}, SeverityGap},
		{ScanFailure{Kind: FailureDetector, Err: errors.New("panic")}, SeverityGap},
	}
	for i, tc := range cases {
		if got := tc.failure.Severity(); got != tc.want {
			t.Errorf("case %d: severity = %s, want %s", i, got, tc.want)
		}
	}

	coverage, _ := PartitionDegradedErrors(errors.Join(
		&DegradedError{Total: 1, Counts: map[FailureKind]int{FailureArchive: 1}, Failures: []ScanFailure{cases[0].failure}},
		&DegradedError{Total: 3, Counts: map[FailureKind]int{FailureSource: 3}, Failures: []ScanFailure{cases[3].failure}},
	))
	if coverage.PolicySkips() != 1 || coverage.Gaps() != 3 {
		t.Fatalf("policy skips=%d gaps=%d, want 1 and 3 (uncounted failures must stay gaps)", coverage.PolicySkips(), coverage.Gaps())
	}
}
