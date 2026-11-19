package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/plenoai/pleno-dlp/pkg/archive"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// FailureKind classifies work the engine could not complete. Verification
// failures are not scan failures: detectors attach those to Result.VerificationErr
// so callers can distinguish an indeterminate credential from missing coverage.
type FailureKind string

const (
	FailureArchive  FailureKind = "archive"
	FailureDetector FailureKind = "detector"
	FailureSource   FailureKind = "source"
)

// ScanFailure describes one unit of incomplete scan coverage.
type ScanFailure struct {
	Kind     FailureKind
	Source   string
	Detector detectors.DetectorType
	Err      error
}

// PolicySkip reports whether the failure is an archive whose expansion the
// scanner declined by design: a safety limit, an unsafe or unsupported entry,
// or a corrupt container. The target was reached and its expansion declined
// deliberately (leaves emitted before the rejection were still scanned), so
// the failure is not reported as an unread scan target.
// Detector failures, timeouts, whole-blob limits, and untyped source errors
// remain coverage gaps.
func (f ScanFailure) PolicySkip() bool {
	return f.Kind != FailureDetector && archiveGapOnly(f.Err, archivePolicyKind)
}

// archivePolicyKind lists archive.PartialError kinds raised while expanding an
// archive that was already reached. Whole-blob kinds (max-blob-bytes,
// corrupt-blob) and git tree errors mean the target was not scanned at all.
func archivePolicyKind(kind string) bool {
	switch kind {
	case "corrupt-archive", "corrupt-entry", "symlink", "special-file",
		"path", "max-depth", "max-files", "max-entry-bytes", "max-input-bytes",
		"max-headers", "central-directory-bytes", "metadata-bytes":
		return true
	}
	return false
}

// ArchiveGapOnly reports whether err contains only typed archive gaps; configured limit gaps require allowLimits.
func ArchiveGapOnly(err error, allowLimits bool) bool {
	return archiveGapOnly(err, func(kind string) bool {
		switch kind {
		case "corrupt-archive", "corrupt-entry", "symlink", "special-file":
			return true
		case "path", "max-depth", "max-files", "max-entry-bytes", "max-input-bytes", "max-blob-bytes",
			"max-headers", "central-directory-bytes", "metadata-bytes":
			return allowLimits
		}
		return false
	})
}

func archiveGapOnly(err error, accept func(kind string) bool) bool {
	if err == nil {
		return false
	}
	if partial, ok := err.(*archive.PartialError); ok {
		return accept(partial.Kind)
	}
	if degraded, ok := err.(*DegradedError); ok {
		if degraded.Total == 0 || degraded.Total != len(degraded.Failures) {
			return false
		}
		for _, failure := range degraded.Failures {
			if failure.Kind == FailureDetector || !archiveGapOnly(failure.Err, accept) {
				return false
			}
		}
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !archiveGapOnly(child, accept) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return archiveGapOnly(wrapped.Unwrap(), accept)
	}
	return false
}

// FailureReason returns a stable reason for a coverage report entry. Typed
// archive failures report only their kind: archive entry names are untrusted
// and stay redacted, so Source is the entry's only locator.
func (f ScanFailure) FailureReason() string {
	var partial *archive.PartialError
	switch {
	case errors.As(f.Err, &partial):
		return partial.Kind
	case errors.Is(f.Err, context.DeadlineExceeded):
		return "deadline-exceeded"
	case f.Err == nil:
		return "unknown"
	}
	return f.Err.Error()
}

// maxFailureExamples bounds diagnostic memory independently of corpus size.
// Gaps and policy skips each retain up to this many examples so a flood of
// skipped archives cannot hide a real gap; Total, Counts, and PolicySkips
// retain complete accounting beyond it.
const maxFailureExamples = 32

// DegradedError reports that a scan produced all available findings but could
// not cover every requested byte or detector. Failures remains structured for
// automation; Error intentionally bounds its detail to avoid enormous CLI
// messages when a provider or corrupt corpus fails repeatedly.
type DegradedError struct {
	Total  int
	Counts map[FailureKind]int
	// Failures contains a bounded set of representative failures.
	// Total can be larger when repeated failures were coalesced for bounded
	// memory use.
	Failures []ScanFailure
	// Classes counts every failure by the installed FailureClassifier, including failures beyond the examples cap.
	Classes map[string]int
	// PolicySkips counts failures for which ScanFailure.PolicySkip holds,
	// including failures beyond the examples cap. The remainder are gaps.
	PolicySkips int
}

// Gaps counts failures whose scan target was not read. Only gaps degrade
// coverage status; policy skips are reported separately.
func (e *DegradedError) Gaps() int {
	if e == nil {
		return 0
	}
	return e.total() - e.PolicySkips
}

// FailureClassifier labels a failure for acceptance policy; an empty label means unclassified.
type FailureClassifier func(ScanFailure) string

var failureClassifier atomic.Pointer[FailureClassifier]

// SetFailureClassifier installs classify and returns a function restoring the previous classifier.
func SetFailureClassifier(classify FailureClassifier) func() {
	var next *FailureClassifier
	if classify != nil {
		next = &classify
	}
	prev := failureClassifier.Swap(next)
	return func() { failureClassifier.Store(prev) }
}

func classifyFailure(classes map[string]int, failure ScanFailure) {
	if classify := failureClassifier.Load(); classify != nil {
		if class := (*classify)(failure); class != "" {
			classes[class]++
		}
	}
}

func (e *DegradedError) Error() string {
	if e == nil || e.total() == 0 {
		return "scan coverage incomplete"
	}
	const maxDetails = 3
	details := make([]string, 0, min(len(e.Failures), maxDetails))
	for i, failure := range e.Failures {
		if i == maxDetails {
			break
		}
		label := string(failure.Kind)
		if failure.Kind == FailureDetector {
			label += " " + failure.Detector.String()
		}
		if failure.Source != "" {
			label += " on " + failure.Source
		}
		details = append(details, fmt.Sprintf("%s: %v", label, failure.Err))
	}
	total := e.total()
	message := fmt.Sprintf("scan coverage incomplete: %d failure(s): %s", total, strings.Join(details, "; "))
	if remaining := total - len(details); remaining > 0 {
		message += fmt.Sprintf("; and %d more", remaining)
	}
	return message
}

func (e *DegradedError) total() int {
	if e.Total > 0 {
		return e.Total
	}
	return len(e.Failures)
}

// Unwrap exposes every underlying failure to errors.Is/errors.As.
func (e *DegradedError) Unwrap() []error {
	if e == nil {
		return nil
	}
	errs := make([]error, 0, len(e.Failures))
	for _, failure := range e.Failures {
		if failure.Err != nil {
			errs = append(errs, failure.Err)
		}
	}
	return errs
}

// PartitionDegradedErrors merges every coverage error in an errors.Join tree
// while returning non-coverage errors separately. Callers must not mistake a
// joined fatal error for a coverage-only result just because errors.As finds
// one DegradedError first.
func PartitionDegradedErrors(err error) (*DegradedError, error) {
	var merged *DegradedError
	var mergedGaps, mergedSkips int
	var residual []error
	var visit func(error)
	visit = func(current error) {
		if current == nil {
			return
		}
		if degraded, ok := current.(*DegradedError); ok {
			if merged == nil {
				merged = &DegradedError{Counts: make(map[FailureKind]int)}
			}
			merged.Total += degraded.total()
			for kind, count := range degraded.Counts {
				merged.Counts[kind] += count
			}
			if degraded.Classes != nil {
				if merged.Classes == nil {
					merged.Classes = make(map[string]int)
				}
				for class, count := range degraded.Classes {
					merged.Classes[class] += count
				}
			} else if len(degraded.Failures) == degraded.total() {
				if merged.Classes == nil {
					merged.Classes = make(map[string]int)
				}
				for _, failure := range degraded.Failures {
					classifyFailure(merged.Classes, failure)
				}
			}
			if len(degraded.Failures) == degraded.total() {
				// Fully enumerated errors (for example built by a source) are
				// classified here so their PolicySkips need not be pre-set.
				for _, failure := range degraded.Failures {
					if failure.PolicySkip() {
						merged.PolicySkips++
					}
				}
			} else {
				merged.PolicySkips += min(max(degraded.PolicySkips, 0), degraded.total())
			}
			for _, failure := range degraded.Failures {
				examples := &mergedGaps
				if failure.PolicySkip() {
					examples = &mergedSkips
				}
				if *examples < maxFailureExamples {
					merged.Failures = append(merged.Failures, failure)
					*examples++
				}
			}
			return
		}
		if joined, ok := current.(interface{ Unwrap() []error }); ok {
			for _, child := range joined.Unwrap() {
				visit(child)
			}
			return
		}
		residual = append(residual, current)
	}
	visit(err)
	return merged, errors.Join(residual...)
}
