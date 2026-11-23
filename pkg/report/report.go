// Package report normalizes scanner reports (pleno-dlp JSON/JSONL, SARIF
// 2.1.0, gitleaks JSON, trufflehog JSON/JSONL) into one redacted finding
// shape, deduplicates them across reports, and renders a self-contained
// HTML viewer.
//
// Redaction invariant: no Finding produced by this package carries a
// complete secret. Importers that receive raw material (gitleaks
// Secret/Match, trufflehog Raw/RawV2) hash it for dedup and pass it
// through detectors.SafeRedacted before the value leaves the importer;
// raw-bearing fields (gitleaks Match/Line, SARIF snippets, trufflehog
// ExtraData) are never read into the normalized shape.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// Finding is the normalized, redacted record shared by every importer and
// by the html output format.
type Finding struct {
	Tool       string   `json:"tool"`
	Detector   string   `json:"detector"`
	Severity   string   `json:"severity,omitempty"`
	Verdict    string   `json:"verdict,omitempty"`
	Redacted   string   `json:"redacted,omitempty"`
	SecretHash string   `json:"secret_hash,omitempty"`
	SourceType string   `json:"source_type,omitempty"`
	Repository string   `json:"repository,omitempty"`
	Commit     string   `json:"commit,omitempty"`
	File       string   `json:"file,omitempty"`
	Line       int      `json:"line,omitempty"`
	Link       string   `json:"link,omitempty"`
	Reports    []string `json:"reports,omitempty"`
	Tools      []string `json:"tools,omitempty"`
}

// HashSecret returns the hex sha256 used by pleno-dlp's secret_hash field,
// so raw-bearing third-party reports dedup against pleno-dlp findings.
func HashSecret(raw string) string {
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Key is the dedup identity: the secret hash when known (it survives tool
// differences in detector naming) otherwise the detector name and display,
// combined with the location.
func (f Finding) Key() string {
	id := f.SecretHash
	if id == "" {
		id = "d:" + strings.ToLower(f.Detector) + "|" + f.Redacted
	}
	return id + "|" + f.Repository + "|" + f.Commit + "|" + f.File + ":" + strconv.Itoa(f.Line)
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func rank(s string) int {
	if r, ok := severityRank[strings.ToLower(s)]; ok {
		return r
	}
	return 5
}

// Merge deduplicates findings by Key, unions the contributing tools and
// reports, prefers the strongest verdict and severity, and returns a
// deterministic order (severity, file, line, detector).
func Merge(in []Finding) []Finding {
	idx := map[string]int{}
	var out []Finding
	for _, f := range in {
		k := f.Key()
		i, ok := idx[k]
		if !ok {
			f.Tools = appendUnique(nil, f.Tools...)
			f.Tools = appendUnique(f.Tools, f.Tool)
			f.Reports = appendUnique(nil, f.Reports...)
			idx[k] = len(out)
			out = append(out, f)
			continue
		}
		m := &out[i]
		m.Tools = appendUnique(m.Tools, append(f.Tools, f.Tool)...)
		m.Reports = appendUnique(m.Reports, f.Reports...)
		if f.Verdict == "verified" {
			m.Verdict = "verified"
		} else if m.Verdict == "" {
			m.Verdict = f.Verdict
		}
		if rank(f.Severity) < rank(m.Severity) {
			m.Severity = f.Severity
		}
		if m.Link == "" {
			m.Link = f.Link
		}
		if m.SourceType == "" {
			m.SourceType = f.SourceType
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		x, y := out[a], out[b]
		if rank(x.Severity) != rank(y.Severity) {
			return rank(x.Severity) < rank(y.Severity)
		}
		if x.File != y.File {
			return x.File < y.File
		}
		if x.Line != y.Line {
			return x.Line < y.Line
		}
		return x.Detector < y.Detector
	})
	return out
}

func appendUnique(dst []string, vals ...string) []string {
	for _, v := range vals {
		if v == "" {
			continue
		}
		dup := false
		for _, d := range dst {
			if d == v {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, v)
		}
	}
	return dst
}
