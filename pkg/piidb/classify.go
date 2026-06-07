package piidb

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/engine"
)

// Thresholds govern when findings are classified as PIIDB candidates.
// Selected through evaluation against representative corpus (see
// classify_test.go for threshold-validation fixtures).
//
// Rationale for threshold selection:
//
//   - ContainerDensity=3: A single file with 1-2 PII mentions is typical
//     of config files, logs, or code comments that incidentally reference
//     a person/email. 3+ PII findings in one container strongly signals
//     a list or table rather than incidental mention. Evaluated against:
//     (a) .env files with 1 email → no escalation (correct)
//     (b) customer_list.csv with 10 emails → escalation (correct)
//     (c) code comment mentioning 2 names → no escalation (correct)
//
//   - ParentDensity=5: A single directory/prefix containing 5+ PII
//     findings across files signals a data-store region. Lower values
//     (2-3) triggered on typical project src/ directories with scattered
//     test fixtures.
//
//   - StructuredFormatBonus: Structured formats (csv, sql, json, tsv,
//     parquet, xlsx) receive a -1 threshold reduction for container
//     density (minimum 2) because structured data inherently has higher
//     PII density per unit. A 2-row CSV with emails is a dataset; a
//     2-mention log line is not.
var Thresholds = struct {
	ContainerDensity      int
	ParentDensity         int
	StructuredFormatBonus int
}{
	ContainerDensity:      3,
	ParentDensity:         5,
	StructuredFormatBonus: 1,
}

// structuredFormats are extensions that indicate machine-readable
// tabular or record-like formats where PII density is inherently
// higher and more likely to represent an actual dataset.
var structuredFormats = map[string]bool{
	"csv":     true,
	"tsv":     true,
	"sql":     true,
	"json":    true,
	"jsonl":   true,
	"ndjson":  true,
	"parquet": true,
	"avro":    true,
	"xlsx":    true,
	"xls":     true,
	"ods":     true,
	"sqlite":  true,
	"db":      true,
	"dump":    true,
	"bak":     true,
}

// IsStructuredFormat reports whether the extension indicates a structured
// data format that receives the format bonus in PIIDB classification.
func IsStructuredFormat(ext string) bool {
	return structuredFormats[strings.ToLower(ext)]
}

// Classification is the PIIDB verdict for a group of findings.
type Classification struct {
	IsCandidate  bool
	Scope        string // "container" or "parent"
	Count        int    // findings in the triggering scope
	ParentCount  int    // findings across the parent scope
	Format       string // detected structured format, or ""
	Reason       string
	NewSeverity  detectors.Severity
	OrigSeverity detectors.Severity
}

type containerGroup struct {
	indices []int
	key     ContainerKey
}

type parentGroup struct {
	indices []int
}

// Classify analyses a set of PII findings and returns per-finding
// classifications. Non-PII findings are returned unmodified with a
// zero Classification. The function is deterministic and goroutine-safe
// (no shared mutable state).
func Classify(findings []engine.Finding) []Classification {
	results := make([]Classification, len(findings))

	containers := make(map[string]*containerGroup)
	parents := make(map[string]*parentGroup)

	for i, f := range findings {
		if !isPII(f) {
			continue
		}
		ck := DeriveContainer(f.Chunk)
		cg, ok := containers[ck.Container]
		if !ok {
			cg = &containerGroup{key: ck}
			containers[ck.Container] = cg
		}
		cg.indices = append(cg.indices, i)

		if ck.Parent != "" {
			pg, ok := parents[ck.Parent]
			if !ok {
				pg = &parentGroup{}
				parents[ck.Parent] = pg
			}
			pg.indices = append(pg.indices, i)
		}
	}

	for _, cg := range containers {
		count := len(cg.indices)
		threshold := Thresholds.ContainerDensity
		isStructured := IsStructuredFormat(cg.key.Extension)
		if isStructured {
			threshold -= Thresholds.StructuredFormatBonus
			if threshold < 2 {
				threshold = 2
			}
		}
		if count < threshold {
			continue
		}
		for _, idx := range cg.indices {
			orig := findings[idx].Result.Severity
			newSev := escalateSeverity(count, isStructured, orig)
			format := ""
			if isStructured {
				format = cg.key.Extension
			}
			reason := fmt.Sprintf("container_density=%d threshold=%d", count, threshold)
			if isStructured {
				reason += " format=" + cg.key.Extension
			}
			results[idx] = Classification{
				IsCandidate:  true,
				Scope:        "container",
				Count:        count,
				ParentCount:  parentCountFor(cg.key.Parent, parents),
				Format:       format,
				Reason:       reason,
				NewSeverity:  newSev,
				OrigSeverity: orig,
			}
		}
	}

	for _, pg := range parents {
		count := len(pg.indices)
		if count < Thresholds.ParentDensity {
			continue
		}
		for _, idx := range pg.indices {
			if results[idx].IsCandidate {
				if results[idx].NewSeverity >= detectors.SeverityHigh {
					continue
				}
			}
			f := findings[idx]
			ck := DeriveContainer(f.Chunk)
			orig := f.Result.Severity
			isStructured := IsStructuredFormat(ck.Extension)
			newSev := escalateFromParent(count, isStructured, orig)
			format := ""
			if isStructured {
				format = ck.Extension
			}
			reason := fmt.Sprintf("parent_density=%d threshold=%d", count, Thresholds.ParentDensity)
			if isStructured {
				reason += " format=" + ck.Extension
			}
			results[idx] = Classification{
				IsCandidate:  true,
				Scope:        "parent",
				Count:        containerCountFor(ck.Container, containers),
				ParentCount:  count,
				Format:       format,
				Reason:       reason,
				NewSeverity:  newSev,
				OrigSeverity: orig,
			}
		}
	}

	return results
}

// ApplyClassification mutates the finding's ExtraData and Severity
// based on the classification result.
func ApplyClassification(f *engine.Finding, c Classification) {
	if !c.IsCandidate {
		return
	}
	if f.Result.ExtraData == nil {
		f.Result.ExtraData = map[string]string{}
	}
	f.Result.ExtraData["pii_db_candidate"] = "true"
	f.Result.ExtraData["pii_db_scope"] = c.Scope
	f.Result.ExtraData["pii_db_count"] = strconv.Itoa(c.Count)
	f.Result.ExtraData["pii_db_parent_count"] = strconv.Itoa(c.ParentCount)
	if c.Format != "" {
		f.Result.ExtraData["pii_db_format"] = c.Format
	}
	f.Result.ExtraData["pii_db_reason"] = c.Reason
	f.Result.Severity = c.NewSeverity
}

// escalateSeverity determines the new severity for container-density
// triggered PIIDB candidates.
//
// Severity model:
//   - Structured format + count >= 5: Critical (confirmed dataset pattern)
//   - Structured format + count >= threshold: High
//   - Unstructured + count >= 10: Critical (overwhelming density)
//   - Unstructured + count >= threshold: High
//
// Never downgrades: if the original severity is already >= the target,
// returns original.
func escalateSeverity(count int, structured bool, orig detectors.Severity) detectors.Severity {
	var target detectors.Severity
	switch {
	case structured && count >= 5:
		target = detectors.SeverityCritical
	case structured:
		target = detectors.SeverityHigh
	case count >= 10:
		target = detectors.SeverityCritical
	default:
		target = detectors.SeverityHigh
	}
	if orig >= target {
		return orig
	}
	return target
}

// escalateFromParent determines severity for parent-density triggered
// candidates. Parent-only triggers (no container-density) are weaker
// evidence so cap at High unless the count is very high.
func escalateFromParent(parentCount int, structured bool, orig detectors.Severity) detectors.Severity {
	var target detectors.Severity
	switch {
	case structured && parentCount >= 10:
		target = detectors.SeverityCritical
	case parentCount >= 20:
		target = detectors.SeverityCritical
	default:
		target = detectors.SeverityHigh
	}
	if orig >= target {
		return orig
	}
	return target
}

func isPII(f engine.Finding) bool {
	if f.Result.ExtraData == nil {
		return false
	}
	return f.Result.ExtraData["finding_class"] == "pii"
}

func parentCountFor(parentKey string, parents map[string]*parentGroup) int {
	if parentKey == "" {
		return 0
	}
	pg, ok := parents[parentKey]
	if !ok {
		return 0
	}
	return len(pg.indices)
}

func containerCountFor(containerKey string, containers map[string]*containerGroup) int {
	cg, ok := containers[containerKey]
	if !ok {
		return 0
	}
	return len(cg.indices)
}
