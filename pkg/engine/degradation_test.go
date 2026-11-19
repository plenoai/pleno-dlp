package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
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

func TestScanFailurePolicySkipSeparatesArchivePolicyFromGaps(t *testing.T) {
	partial := func(kind string) error {
		return &archive.PartialError{Kind: kind, Entry: "e", Err: io.ErrUnexpectedEOF}
	}
	for _, tc := range []struct {
		name    string
		failure ScanFailure
		want    bool
	}{
		{"symlink", ScanFailure{Kind: FailureArchive, Err: &redactedArchiveCoverageError{cause: partial("symlink")}}, true},
		{"corrupt-entry", ScanFailure{Kind: FailureArchive, Err: partial("corrupt-entry")}, true},
		{"unsafe-path", ScanFailure{Kind: FailureArchive, Err: partial("path")}, true},
		{"max-headers", ScanFailure{Kind: FailureArchive, Err: partial("max-headers")}, true},
		{"git-walker-max-depth", ScanFailure{Kind: FailureSource, Err: fmt.Errorf("walk: %w", partial("max-depth"))}, true},
		{"joined-policy", ScanFailure{Kind: FailureArchive, Err: errors.Join(partial("max-entry-bytes"), partial("corrupt-archive"))}, true},
		{"timeout", ScanFailure{Kind: FailureArchive, Err: errors.Join(partial("corrupt-entry"), context.DeadlineExceeded)}, false},
		{"whole-blob-limit", ScanFailure{Kind: FailureSource, Err: partial("max-blob-bytes")}, false},
		{"corrupt-blob", ScanFailure{Kind: FailureSource, Err: partial("corrupt-blob")}, false},
		{"tree-diff", ScanFailure{Kind: FailureSource, Err: errors.New("tree-diff: git: parse native log")}, false},
		{"detector", ScanFailure{Kind: FailureDetector, Err: partial("symlink")}, false},
		{"untyped-archive", ScanFailure{Kind: FailureArchive, Err: &redactedArchiveCoverageError{cause: io.ErrUnexpectedEOF}}, false},
	} {
		if got := tc.failure.PolicySkip(); got != tc.want {
			t.Errorf("%s: PolicySkip() = %t, want %t", tc.name, got, tc.want)
		}
	}
}

func TestScanFailureReasonKeepsArchiveEntryRedacted(t *testing.T) {
	failure := ScanFailure{Kind: FailureArchive, Err: &redactedArchiveCoverageError{
		cause: &archive.PartialError{Kind: "symlink", Entry: "credential-like-entry", Err: io.ErrUnexpectedEOF},
	}}
	if got := failure.FailureReason(); got != "symlink" {
		t.Fatalf("reason = %q, want typed kind only", got)
	}
	gap := ScanFailure{Kind: FailureSource, Err: errors.New("tree-diff: git: parse native log")}
	if got := gap.FailureReason(); got != "tree-diff: git: parse native log" {
		t.Fatalf("reason = %q", got)
	}
}

func TestEngineRetainsGapExamplesBeyondPolicySkipFlood(t *testing.T) {
	eng := NewWithDetectors(nil, Options{Concurrency: 1}, nil)
	eng.resetFailures()
	skip := ScanFailure{Kind: FailureArchive, Source: "vendor.gem", Err: &archive.PartialError{Kind: "symlink"}}
	for range maxFailureExamples * 3 {
		eng.recordFailure(skip)
	}
	eng.recordFailure(ScanFailure{Kind: FailureSource, Source: "repo", Err: errors.New("tree-diff")})
	var degraded *DegradedError
	if !errors.As(eng.takeFailures(), &degraded) {
		t.Fatal("want DegradedError")
	}
	if degraded.Total != maxFailureExamples*3+1 || degraded.PolicySkips != maxFailureExamples*3 || degraded.Gaps() != 1 {
		t.Fatalf("total=%d skips=%d gaps=%d", degraded.Total, degraded.PolicySkips, degraded.Gaps())
	}
	if len(degraded.Failures) != maxFailureExamples+1 || degraded.Failures[maxFailureExamples].Source != "repo" {
		t.Fatalf("gap example was not retained: %d examples", len(degraded.Failures))
	}
	merged, residual := PartitionDegradedErrors(errors.Join(degraded, &DegradedError{
		Total: 1, Counts: map[FailureKind]int{FailureArchive: 1},
		Failures: []ScanFailure{skip},
	}))
	if residual != nil || merged.Total != degraded.Total+1 || merged.PolicySkips != degraded.PolicySkips+1 || merged.Gaps() != 1 {
		t.Fatalf("merged total=%d skips=%d gaps=%d residual=%v", merged.Total, merged.PolicySkips, merged.Gaps(), residual)
	}
	if len(merged.Failures) != maxFailureExamples+1 {
		t.Fatalf("merged examples = %d, want per-severity cap", len(merged.Failures))
	}
}
