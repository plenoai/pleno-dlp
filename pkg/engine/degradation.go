package engine

import (
	"fmt"
	"strings"

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

// maxFailureExamples bounds diagnostic memory independently of corpus size.
// Total and Counts retain complete accounting after this many examples.
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
