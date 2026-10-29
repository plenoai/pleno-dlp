package crash

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// RedactWithPII runs an already initialized PII detector before pattern
// redaction can remove context. Errors never return the unredacted input.
// The caller must bound ctx and exclude pii from r.Detectors.
func (r *Redactor) RedactWithPII(ctx context.Context, text string, pii detectors.Detector) (out string, err error) {
	if pii == nil {
		return r.Redact(text), nil
	}
	defer func() {
		if recover() != nil {
			out, err = "", fmt.Errorf("feedback: PII redaction panicked")
		}
	}()
	if !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
		return "", fmt.Errorf("feedback: PII redaction requires UTF-8 text without NUL bytes")
	}
	if ctx.Err() != nil {
		return "", fmt.Errorf("feedback: PII redaction cancelled")
	}
	results, scanErr := pii.FromData(ctx, false, []byte(text))
	if scanErr != nil || ctx.Err() != nil {
		// Engine errors may quote the input; do not expose their text.
		return "", fmt.Errorf("feedback: PII redaction failed")
	}
	hidden := make([]bool, len(text))
	for _, result := range results {
		if len(result.Raw) == 0 && len(result.RawV2) == 0 {
			return "", fmt.Errorf("feedback: PII redaction returned an empty match")
		}
		for _, raw := range [][]byte{result.Raw, result.RawV2} {
			if len(raw) > 0 {
				for offset := 0; offset < len(text); {
					index := strings.Index(text[offset:], string(raw))
					if index < 0 {
						break
					}
					start := offset + index
					for i := start; i < start+len(raw); i++ {
						hidden[i] = true
					}
					offset = start + 1
				}
			}
		}
	}
	// Union overlapping matches against the original text before replacing them.
	var redacted strings.Builder
	for i := 0; i < len(text); i++ {
		if !hidden[i] {
			redacted.WriteByte(text[i])
		} else if i == 0 || !hidden[i-1] {
			redacted.WriteString("[PII]")
		}
	}
	return r.Redact(redacted.String()), nil
}
