package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
)

// parsePlenoDLP reads the JSON array `pleno-dlp scan ... --format json`
// emits (see pkg/output/json.go's jsonRecord). Only the two fields the
// harness needs are decoded; unknown fields are ignored so this parser
// doesn't need to track every schema addition.
func parsePlenoDLP(data []byte) ([]finding, error) {
	var recs []struct {
		Detector string `json:"detector"`
		Source   struct {
			Metadata map[string]any `json:"metadata"`
		} `json:"source"`
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(data, &recs); err != nil {
		return nil, fmt.Errorf("parsePlenoDLP: %w", err)
	}
	out := make([]finding, 0, len(recs))
	for _, r := range recs {
		path, _ := r.Source.Metadata["path"].(string)
		if path == "" {
			continue
		}
		out = append(out, finding{Tool: "pleno-dlp", File: path, Name: r.Detector})
	}
	return out, nil
}

// parseTrufflehog reads trufflehog's NDJSON (one JSON object per line,
// `--json`). Filesystem-source lines carry the path at
// SourceMetadata.Data.Filesystem.file; other source shapes (git, etc.)
// are out of scope for the dir-mode corpora this harness runs.
func parseTrufflehog(data []byte) ([]finding, error) {
	var out []finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec struct {
			SourceMetadata struct {
				Data struct {
					Filesystem struct {
						File string `json:"file"`
					} `json:"Filesystem"`
				} `json:"Data"`
			} `json:"SourceMetadata"`
			DetectorName string `json:"DetectorName"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("parseTrufflehog: %w", err)
		}
		path := rec.SourceMetadata.Data.Filesystem.File
		if path == "" {
			continue
		}
		out = append(out, finding{Tool: "trufflehog", File: path, Name: rec.DetectorName})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parseTrufflehog: %w", err)
	}
	return out, nil
}

// parseGitleaks reads a gitleaks `--report-format json` report: a JSON
// array with a File and RuleID per finding.
func parseGitleaks(data []byte) ([]finding, error) {
	var recs []struct {
		File   string `json:"File"`
		RuleID string `json:"RuleID"`
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(data, &recs); err != nil {
		return nil, fmt.Errorf("parseGitleaks: %w", err)
	}
	out := make([]finding, 0, len(recs))
	for _, r := range recs {
		if r.File == "" {
			continue
		}
		out = append(out, finding{Tool: "gitleaks", File: r.File, Name: r.RuleID})
	}
	return out, nil
}
