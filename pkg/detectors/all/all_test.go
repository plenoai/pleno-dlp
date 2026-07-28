package all

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// TestContractType verifies that every registered detector reports a known
// (non-Unknown) type.
func TestContractType(t *testing.T) {
	t.Parallel()
	for _, d := range detectors.All() {
		d := d
		t.Run(d.Type().String(), func(t *testing.T) {
			t.Parallel()
			if d.Type() == detectors.Unknown {
				t.Errorf("detector %T has Type() == Unknown", d)
			}
		})
	}
}

// TestContractKeywords verifies that every detector provides at least one
// non-empty keyword used for pre-filter matching. Keywords may be mixed-case
// — the scanner lowercases the haystack but keeps the keyword as-is for
// literal match; therefore we only assert non-empty.
func TestContractKeywords(t *testing.T) {
	t.Parallel()
	for _, d := range detectors.All() {
		d := d
		t.Run(d.Type().String(), func(t *testing.T) {
			t.Parallel()
			kws := d.Keywords()
			if len(kws) == 0 {
				t.Errorf("detector %T (%s) returned no keywords", d, d.Type())
				return
			}
			for i, kw := range kws {
				if kw == "" {
					t.Errorf("detector %T (%s) keyword[%d] is empty", d, d.Type(), i)
				}
			}
		})
	}
}

// TestContractFromData_NilData verifies that FromData with nil data does not
// panic and returns either (nil, nil) or (empty slice, nil).
func TestContractFromData_NilData(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, d := range detectors.All() {
		d := d
		t.Run(d.Type().String(), func(t *testing.T) {
			t.Parallel()
			results, err := d.FromData(ctx, false, nil)
			if err != nil {
				t.Errorf("detector %T (%s) returned non-nil error for nil data: %v", d, d.Type(), err)
			}
			if len(results) != 0 {
				t.Errorf("detector %T (%s) returned %d results for nil data, want 0", d, d.Type(), len(results))
			}
		})
	}
}

// TestContractFromData_EmptyData verifies that FromData with an empty byte
// slice does not panic and returns either (nil, nil) or (empty slice, nil).
func TestContractFromData_EmptyData(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, d := range detectors.All() {
		d := d
		t.Run(d.Type().String(), func(t *testing.T) {
			t.Parallel()
			results, err := d.FromData(ctx, false, []byte{})
			if err != nil {
				t.Errorf("detector %T (%s) returned non-nil error for empty data: %v", d, d.Type(), err)
			}
			if len(results) != 0 {
				t.Errorf("detector %T (%s) returned %d results for empty data, want 0", d, d.Type(), len(results))
			}
		})
	}
}

// TestContractRegistrationCount is a sanity check that all.go's blank-imports
// are wiring detectors into the registry as expected.
func TestContractRegistrationCount(t *testing.T) {
	t.Parallel()
	count := len(detectors.All())
	if count <= 500 {
		t.Errorf("expected > 500 registered detectors, got %d — check all.go imports", count)
	}
}

// TestContractNoDuplicateTypes verifies that no two detectors share the same
// DetectorType. The registry already panics on duplicate registration via
// Register(), but this test makes the constraint explicit and visible in CI
// output.
func TestContractNoDuplicateTypes(t *testing.T) {
	t.Parallel()
	seen := make(map[detectors.DetectorType]string)
	for _, d := range detectors.All() {
		dt := d.Type()
		if prev, ok := seen[dt]; ok {
			t.Errorf("duplicate DetectorType %s (%d): already registered by %s, also registered by %T", dt, dt, prev, d)
		} else {
			seen[dt] = dt.String()
		}
	}
}

// TestContractVerificationCacheInputDependentSet pins the audited set of
// detectors whose provider verification uses context outside Raw and RawV2.
// Update this set only after auditing a detector's verified FromData path.
func TestContractVerificationCacheInputDependentSet(t *testing.T) {
	t.Parallel()
	want := map[detectors.DetectorType]bool{
		detectors.AWSSession:      true,
		detectors.AzureAD:         true,
		detectors.AzureApp:        true,
		detectors.AzureStorageKey: true,
		detectors.Cloudinary:      true,
		detectors.Databricks:      true,
		detectors.Freshdesk:       true,
		detectors.JFrog:           true,
		detectors.Kubeconfig:      true,
		detectors.Supabase:        true,
		detectors.Weaviate:        true,
		detectors.Zendesk:         true,
	}
	got := make(map[detectors.DetectorType]bool)
	for _, d := range detectors.All() {
		contextual, ok := d.(detectors.VerificationCacheInputDependent)
		if !ok || !contextual.VerificationCacheUsesFullInput() {
			continue
		}
		if _, ok := d.(detectors.Verifier); !ok {
			t.Errorf("input-dependent detector %T (%s) is not a Verifier", d, d.Type())
		}
		got[d.Type()] = true
	}
	for detectorType := range want {
		if !got[detectorType] {
			t.Errorf("input-dependent detector %s is missing its cache marker", detectorType)
		}
	}
	for detectorType := range got {
		if !want[detectorType] {
			t.Errorf("detector %s has an unaudited input-dependent cache marker", detectorType)
		}
	}
}
