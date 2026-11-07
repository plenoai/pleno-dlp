package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/engine"
)

const maxFeedbackScanBytes int64 = 64 << 20

var feedbackDetectorName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// feedbackScanMatch rescans a local file through the offline engine and
// selects the result identified by a scan-output SHA-256 value.
func feedbackScanMatch(ctx context.Context, path, detector, findingHash string) (detectors.Result, error) {
	if path == "" || detector == "" || !feedbackDetectorName.MatchString(detector) || !validFindingHash(findingHash) {
		return detectors.Result{}, fmt.Errorf("feedback: false-positive reports require --scan-file, a valid --detector, and a 64-character --finding-hash")
	}
	pathInfo, err := os.Stat(path)
	if err != nil {
		return detectors.Result{}, fmt.Errorf("feedback: stat scan file: %w", err)
	}
	if !pathInfo.Mode().IsRegular() {
		return detectors.Result{}, fmt.Errorf("feedback: --scan-file must be a regular file")
	}
	if pathInfo.Size() > maxFeedbackScanBytes {
		return detectors.Result{}, fmt.Errorf("feedback: scan file exceeds %d bytes", maxFeedbackScanBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return detectors.Result{}, fmt.Errorf("feedback: open scan file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return detectors.Result{}, fmt.Errorf("feedback: stat scan file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return detectors.Result{}, fmt.Errorf("feedback: --scan-file must be a regular file")
	}
	if info.Size() > maxFeedbackScanBytes {
		return detectors.Result{}, fmt.Errorf("feedback: scan file exceeds %d bytes", maxFeedbackScanBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxFeedbackScanBytes+1))
	if err != nil {
		return detectors.Result{}, fmt.Errorf("feedback: read scan file: %w", err)
	}
	if int64(len(data)) > maxFeedbackScanBytes {
		return detectors.Result{}, fmt.Errorf("feedback: scan file exceeds %d bytes", maxFeedbackScanBytes)
	}
	var selected []detectors.Detector
	for _, d := range detectors.All() {
		if d.Type().String() == detector {
			if !feedbackScannableDetector(d.Type()) {
				return detectors.Result{}, fmt.Errorf("feedback: detector %q is not a secret detector", detector)
			}
			selected = append(selected, d)
		}
	}
	if len(selected) == 0 {
		return detectors.Result{}, fmt.Errorf("feedback: unknown detector %q", detector)
	}
	results, err := engine.ScanBytesWithDetectors(ctx, selected, data, engine.Options{Concurrency: 1})
	if err != nil {
		return detectors.Result{}, fmt.Errorf("feedback: scan file offline: %w", err)
	}
	var match detectors.Result
	found := false
	for _, result := range results {
		if result.DetectorType.String() == detector && (rawHash(result.Raw) == findingHash || rawHash(result.RawV2) == findingHash) {
			if found && (!bytes.Equal(match.Raw, result.Raw) || !bytes.Equal(match.RawV2, result.RawV2) || match.SafeRedacted() != result.SafeRedacted()) {
				return detectors.Result{}, fmt.Errorf("feedback: finding hash %q matches multiple %s results; use a unique secret hash", findingHash, detector)
			}
			match, found = result, true
		}
	}
	if !found {
		return detectors.Result{}, fmt.Errorf("feedback: finding hash did not match detector %s in --scan-file", detector)
	}
	return match, nil
}

func feedbackScannableDetector(t detectors.DetectorType) bool {
	switch t {
	case detectors.PIIEmail, detectors.PIIUSSSN, detectors.PIICreditCard, detectors.PIIIBAN,
		detectors.PIIAnonymize, detectors.PIIOpenAIPF:
		return false
	default:
		return true
	}
}

func rawHash(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validFindingHash(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
