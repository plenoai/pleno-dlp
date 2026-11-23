package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// BaselineVersion is the on-disk schema version of a baseline file.
const BaselineVersion = 1

// Baseline is the on-disk set of accepted findings, keyed by Fingerprint.
// It never stores raw secrets: only the fingerprint plus the redacted
// display, detector, and path so reviewers can audit the file in a diff.
type Baseline struct {
	Version  int             `json:"version"`
	Findings []BaselineEntry `json:"findings"`
}

// BaselineEntry is one accepted finding.
type BaselineEntry struct {
	Fingerprint string `json:"fingerprint"`
	Detector    string `json:"detector,omitempty"`
	Path        string `json:"path,omitempty"`
	Redacted    string `json:"redacted,omitempty"`
}

// LoadBaseline parses a baseline file and rejects unknown versions and
// entries without a fingerprint.
func LoadBaseline(r io.Reader) (*Baseline, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var b Baseline
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("baseline: invalid json: %w", err)
	}
	if b.Version != BaselineVersion {
		return nil, fmt.Errorf("baseline: unsupported version %d (want %d)", b.Version, BaselineVersion)
	}
	for i, e := range b.Findings {
		if e.Fingerprint == "" {
			return nil, fmt.Errorf("baseline entry %d: fingerprint is required", i)
		}
	}
	return &b, nil
}

// LoadBaselineFile opens path and delegates to LoadBaseline.
func LoadBaselineFile(path string) (*Baseline, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("baseline: open %s: %w", path, err)
	}
	defer f.Close()
	return LoadBaseline(f)
}

// Fingerprints returns every fingerprint in the baseline.
func (b *Baseline) Fingerprints() []string {
	if b == nil {
		return nil
	}
	out := make([]string, 0, len(b.Findings))
	for _, e := range b.Findings {
		out = append(out, e.Fingerprint)
	}
	return out
}

// Normalize deduplicates by fingerprint (first entry wins) and sorts by
// path, detector, then fingerprint so regenerating a baseline yields a
// minimal, deterministic diff.
func (b *Baseline) Normalize() {
	b.Version = BaselineVersion
	seen := make(map[string]struct{}, len(b.Findings))
	out := b.Findings[:0]
	for _, e := range b.Findings {
		if _, ok := seen[e.Fingerprint]; ok || e.Fingerprint == "" {
			continue
		}
		seen[e.Fingerprint] = struct{}{}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		if out[i].Detector != out[j].Detector {
			return out[i].Detector < out[j].Detector
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	if out == nil {
		out = []BaselineEntry{}
	}
	b.Findings = out
}

// Merge returns the baseline that results from updating b with the entries
// of current. When prune is true, entries absent from current (fixed or
// removed secrets) are dropped; otherwise they are retained. Existing
// entries keep their position-independent identity: only the fingerprint
// matters.
func (b *Baseline) Merge(current []BaselineEntry, prune bool) (merged *Baseline, added, removed int) {
	old := map[string]BaselineEntry{}
	if b != nil {
		for _, e := range b.Findings {
			old[e.Fingerprint] = e
		}
	}
	cur := map[string]struct{}{}
	merged = &Baseline{Version: BaselineVersion}
	for _, e := range current {
		if e.Fingerprint == "" {
			continue
		}
		if _, dup := cur[e.Fingerprint]; dup {
			continue
		}
		cur[e.Fingerprint] = struct{}{}
		if _, ok := old[e.Fingerprint]; !ok {
			added++
		}
		merged.Findings = append(merged.Findings, e)
	}
	for fp, e := range old {
		if _, ok := cur[fp]; ok {
			continue
		}
		if prune {
			removed++
			continue
		}
		merged.Findings = append(merged.Findings, e)
	}
	merged.Normalize()
	return merged, added, removed
}

// WriteBaselineFile atomically writes b to path (temp file + rename) so an
// interrupted update never leaves a truncated baseline that would suddenly
// un-suppress every accepted finding.
func WriteBaselineFile(path string, b *Baseline) error {
	b.Normalize()
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("baseline: encode: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".pleno-baseline-*.tmp")
	if err != nil {
		return fmt.Errorf("baseline: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("baseline: write: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("baseline: chmod: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("baseline: close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("baseline: rename: %w", err)
	}
	return nil
}
