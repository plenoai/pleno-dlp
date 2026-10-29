package crash

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

type feedbackPIIDetector struct {
	fromData func(context.Context, bool, []byte) ([]detectors.Result, error)
}

func (feedbackPIIDetector) Keywords() []string           { return nil }
func (feedbackPIIDetector) Type() detectors.DetectorType { return detectors.PIIAnonymize }
func (d feedbackPIIDetector) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	return d.fromData(ctx, verify, data)
}

func TestRedactWithPIIRetainsContextAndRemovesJapaneseNames(t *testing.T) {
	input := "山田太郎 works at 株式会社架空; contact alice@example.com"
	d := feedbackPIIDetector{fromData: func(_ context.Context, verify bool, data []byte) ([]detectors.Result, error) {
		if verify || string(data) != input {
			t.Fatalf("PII must receive original text offline")
		}
		return []detectors.Result{{Raw: []byte("山田太郎"), RawV2: []byte("株式会社架空")}}, nil
	}}
	got, err := (&Redactor{}).RedactWithPII(context.Background(), input, d)
	if err != nil || got != "[PII] works at [PII]; contact [EMAIL]" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestRedactWithPIIFailsWithoutReturningInput(t *testing.T) {
	for _, mode := range []string{"error", "panic", "cancelled", "cancel_during", "invalid_utf8", "nul", "empty_match"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			input := "山田太郎"
			switch mode {
			case "cancelled":
				cancel()
			case "invalid_utf8":
				input += "\xff"
			case "nul":
				input += "\x00"
			}
			d := feedbackPIIDetector{fromData: func(context.Context, bool, []byte) ([]detectors.Result, error) {
				switch mode {
				case "panic":
					panic(input)
				case "error":
					return nil, errors.New(input)
				case "cancel_during":
					cancel()
					return nil, nil
				case "empty_match":
					return []detectors.Result{{}}, nil
				default:
					t.Fatal("invalid input must not reach the engine")
					return nil, nil
				}
			}}
			got, err := (&Redactor{}).RedactWithPII(ctx, input, d)
			if got != "" || err == nil || strings.Contains(err.Error(), "山田太郎") {
				t.Fatalf("failure leaked input or was ignored: %q, %v", got, err)
			}
		})
	}
}

func TestRedactWithPIIDisabledUsesPatterns(t *testing.T) {
	got, err := (&Redactor{}).RedactWithPII(context.Background(), "alice@example.com", nil)
	if err != nil || got != "[EMAIL]" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestRedactWithPIIRemovesEnclosingMatchesFirst(t *testing.T) {
	d := feedbackPIIDetector{fromData: func(context.Context, bool, []byte) ([]detectors.Result, error) {
		return []detectors.Result{{Raw: []byte("山田")}, {Raw: []byte("山田太郎")}}, nil
	}}
	got, err := (&Redactor{}).RedactWithPII(context.Background(), "山田太郎", d)
	if err != nil || got != "[PII]" {
		t.Fatalf("overlapping match exposed a suffix: %q, %v", got, err)
	}
}

func TestRedactWithPIIUnionsPartiallyOverlappingMatches(t *testing.T) {
	d := feedbackPIIDetector{fromData: func(context.Context, bool, []byte) ([]detectors.Result, error) {
		return []detectors.Result{{Raw: []byte("山田太")}, {Raw: []byte("田太郎")}}, nil
	}}
	got, err := (&Redactor{}).RedactWithPII(context.Background(), "山田太郎", d)
	if err != nil || got != "[PII]" {
		t.Fatalf("overlapping match exposed text: %q, %v", got, err)
	}
}
