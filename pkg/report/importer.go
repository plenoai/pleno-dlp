package report

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// MaxReportBytes bounds one imported report so a hostile or mistaken input
// cannot exhaust memory.
const MaxReportBytes = 512 << 20

// Format names returned by Detect.
const (
	FormatPleno      = "pleno"
	FormatSARIF      = "sarif"
	FormatGitleaks   = "gitleaks"
	FormatTrufflehog = "trufflehog"
)

// ImportFile reads and normalizes one report file.
func ImportFile(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out, err := Import(f, filepath.Base(path))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

// Import auto-detects the report format and normalizes every finding. label
// names the report in Finding.Reports.
func Import(r io.Reader, label string) ([]Finding, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxReportBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxReportBytes {
		return nil, fmt.Errorf("report exceeds %d bytes", MaxReportBytes)
	}
	data = bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")))
	if len(data) == 0 {
		return nil, nil
	}
	var objs []map[string]json.RawMessage
	switch data[0] {
	case '[':
		if err := json.Unmarshal(data, &objs); err != nil {
			return nil, fmt.Errorf("parse JSON array: %w", err)
		}
	case '{':
		var one map[string]json.RawMessage
		if err := json.Unmarshal(data, &one); err == nil {
			if _, ok := one["runs"]; ok {
				return importSARIF(data, label)
			}
			objs = []map[string]json.RawMessage{one}
		} else {
			objs, err = splitJSONL(data)
			if err != nil {
				return nil, err
			}
		}
	default:
		return nil, errors.New("unrecognized report: expected JSON, JSONL, or SARIF")
	}
	out := make([]Finding, 0, len(objs))
	for i, o := range objs {
		f, err := importObject(o)
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", i+1, err)
		}
		f.Reports = []string{label}
		out = append(out, f)
	}
	return out, nil
}

func splitJSONL(data []byte) ([]map[string]json.RawMessage, error) {
	var out []map[string]json.RawMessage
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), MaxReportBytes)
	n := 0
	for sc.Scan() {
		n++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var o map[string]json.RawMessage
		if err := json.Unmarshal(line, &o); err != nil {
			return nil, fmt.Errorf("parse JSONL line %d: %w", n, err)
		}
		out = append(out, o)
	}
	return out, sc.Err()
}

// Detect classifies one JSON object by its distinguishing keys.
func Detect(o map[string]json.RawMessage) string {
	switch {
	case has(o, "detector") && has(o, "source"):
		return FormatPleno
	case has(o, "RuleID"):
		return FormatGitleaks
	case has(o, "DetectorName") || has(o, "DetectorType"):
		return FormatTrufflehog
	}
	return ""
}

func has(o map[string]json.RawMessage, k string) bool { _, ok := o[k]; return ok }

func importObject(o map[string]json.RawMessage) (Finding, error) {
	raw, _ := json.Marshal(o)
	switch Detect(o) {
	case FormatPleno:
		return importPleno(raw)
	case FormatGitleaks:
		return importGitleaks(raw)
	case FormatTrufflehog:
		return importTrufflehog(raw)
	}
	return Finding{}, errors.New("unrecognized finding shape (expected pleno-dlp, gitleaks, or trufflehog)")
}

type plenoRecord struct {
	Detector   string `json:"detector"`
	Verdict    string `json:"verdict"`
	Severity   string `json:"severity"`
	Redacted   string `json:"redacted"`
	SecretHash string `json:"secret_hash"`
	Source     struct {
		Type     string         `json:"type"`
		Metadata map[string]any `json:"metadata"`
	} `json:"source"`
}

func importPleno(raw []byte) (Finding, error) {
	var r plenoRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return Finding{}, err
	}
	md := r.Source.Metadata
	f := Finding{
		Tool:       "pleno-dlp",
		Detector:   r.Detector,
		Severity:   strings.ToLower(r.Severity),
		Verdict:    r.Verdict,
		Redacted:   r.Redacted,
		SecretHash: r.SecretHash,
		SourceType: r.Source.Type,
		Repository: str(md, "repository"),
		Commit:     str(md, "commit"),
		File:       firstNonEmpty(str(md, "file"), str(md, "path"), str(md, "key"), str(md, "object"), str(md, "label")),
		Line:       num(md, "line"),
		Link:       str(md, "link"),
	}
	return f, nil
}

type gitleaksRecord struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	File        string `json:"File"`
	Commit      string `json:"Commit"`
	Link        string `json:"Link"`
	Secret      string `json:"Secret"`
	// Match and Line also carry the secret; they are deliberately not
	// decoded so they cannot leak into the normalized record.
}

func importGitleaks(raw []byte) (Finding, error) {
	var r gitleaksRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return Finding{}, err
	}
	return Finding{
		Tool:       "gitleaks",
		Detector:   r.RuleID,
		Redacted:   detectors.Redact([]byte(r.Secret), nil),
		SecretHash: HashSecret(r.Secret),
		Commit:     r.Commit,
		File:       r.File,
		Line:       r.StartLine,
		Link:       r.Link,
		SourceType: sourceTypeFor(r.Commit),
	}, nil
}

func sourceTypeFor(commit string) string {
	if commit != "" {
		return "git"
	}
	return "filesystem"
}

type trufflehogRecord struct {
	DetectorName   string `json:"DetectorName"`
	Verified       bool   `json:"Verified"`
	VerifyErr      string `json:"VerificationError"`
	Raw            string `json:"Raw"`
	RawV2          string `json:"RawV2"`
	Redacted       string `json:"Redacted"`
	SourceName     string `json:"SourceName"`
	SourceMetadata struct {
		Data map[string]map[string]any `json:"Data"`
	} `json:"SourceMetadata"`
}

func importTrufflehog(raw []byte) (Finding, error) {
	var r trufflehogRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return Finding{}, err
	}
	f := Finding{
		Tool:       "trufflehog",
		Detector:   r.DetectorName,
		Redacted:   detectors.SafeRedacted(r.Redacted, []byte(r.Raw), []byte(r.RawV2)),
		SecretHash: HashSecret(r.Raw),
		Verdict:    "unverified",
	}
	switch {
	case r.Verified:
		f.Verdict = "verified"
	case r.VerifyErr != "":
		f.Verdict = "indeterminate"
	}
	kinds := make([]string, 0, len(r.SourceMetadata.Data))
	for kind := range r.SourceMetadata.Data {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	if len(kinds) > 0 {
		md := r.SourceMetadata.Data[kinds[0]]
		f.SourceType = strings.ToLower(kinds[0])
		f.Repository = str(md, "repository")
		f.Commit = str(md, "commit")
		f.File = firstNonEmpty(str(md, "file"), str(md, "path"))
		f.Line = num(md, "line")
		f.Link = str(md, "link")
	}
	return f, nil
}

type sarifLog struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Name string `json:"name"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
						// snippet is deliberately not decoded: gitleaks and
						// other producers put the matched secret there.
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			Properties map[string]any `json:"properties"`
		} `json:"results"`
	} `json:"runs"`
}

func importSARIF(data []byte, label string) ([]Finding, error) {
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("parse SARIF: %w", err)
	}
	var out []Finding
	for _, run := range log.Runs {
		tool := run.Tool.Driver.Name
		if tool == "" {
			tool = "sarif"
		}
		for _, res := range run.Results {
			f := Finding{
				Tool:     tool,
				Detector: res.RuleID,
				Severity: firstNonEmpty(strings.ToLower(str(res.Properties, "severity")), severityForLevel(res.Level)),
				Verdict:  str(res.Properties, "verdict"),
				Redacted: res.Message.Text,
				Reports:  []string{label},
			}
			if len(res.Locations) > 0 {
				pl := res.Locations[0].PhysicalLocation
				f.File = pl.ArtifactLocation.URI
				f.Line = pl.Region.StartLine
			}
			out = append(out, f)
		}
	}
	return out, nil
}

func severityForLevel(level string) string {
	switch level {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "note":
		return "low"
	}
	return ""
}

func str(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func num(m map[string]any, k string) int {
	switch v := m[k].(type) {
	case float64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	}
	return 0
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
