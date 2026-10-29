package detectors

import (
	"bytes"
)

// SafeRedacted preserves a detector's existing display when it does not
// contain either complete secret. Unsafe or empty displays are replaced by a
// common mask derived from Raw, falling back to RawV2 when Raw is absent.
func SafeRedacted(candidate string, raw, rawV2 []byte) string {
	if candidate != "" && !containsSecret(candidate, raw) && !containsSecret(candidate, rawV2) {
		return candidate
	}
	return Redact(raw, rawV2)
}

// Redact returns a bounded display for a secret pair. Values up to six runes
// are fully hidden; longer values retain six leading runes and an ellipsis.
// The final containment checks also protect short RawV2 values that happen to
// occur inside Raw's visible prefix.
func Redact(raw, rawV2 []byte) string {
	primary := raw
	if len(primary) == 0 {
		primary = rawV2
	}
	if len(primary) == 0 {
		return ""
	}

	runes := []rune(string(primary))
	candidate := safeMarker(raw, rawV2)
	if len(runes) > 6 {
		candidate = string(runes[:6]) + "..."
	}
	if containsSecret(candidate, raw) || containsSecret(candidate, rawV2) {
		return safeMarker(raw, rawV2)
	}
	return candidate
}

func containsSecret(candidate string, secret []byte) bool {
	return len(secret) > 0 && bytes.Contains([]byte(candidate), secret)
}

func safeMarker(raw, rawV2 []byte) string {
	for _, marker := range []string{"***", "...", "(redacted)", "[hidden]"} {
		if !containsSecret(marker, raw) && !containsSecret(marker, rawV2) {
			return marker
		}
	}
	return ""
}

// SafeResults enforces the display contract on every result before a detector returns.
func SafeResults(results []Result) []Result {
	for i := range results {
		results[i].Redacted = results[i].SafeRedacted()
	}
	return results
}
