package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MaxSpoolFiles caps retained per-report files; last.json is not counted.
const MaxSpoolFiles = 20

// LastFile is the name of the most recent report in the spool.
const LastFile = "last.json"

// Spool writes the report to <dir>/<kind>-<id>-<unix>.json and
// <dir>/last.json, then prunes the oldest files beyond MaxSpoolFiles.
// <id> is the crash fingerprint, or for other kinds the first 16 hex
// characters of the SHA-256 of the encoded report. It returns the
// per-report path.
func Spool(dir string, r Report) (string, error) {
	b, err := Marshal(r)
	if err != nil {
		return "", err
	}
	id := r.Fingerprint
	if r.Kind != KindCrash || !fingerprintRe.MatchString(id) {
		sum := sha256.Sum256(b)
		id = hex.EncodeToString(sum[:])[:16]
	}
	path := filepath.Join(dir, fmt.Sprintf("%s-%s-%d.json", r.Kind, id, r.CreatedAt.Unix()))
	if err := writePrivate(dir, path, b); err != nil {
		return "", err
	}
	if err := writePrivate(dir, filepath.Join(dir, LastFile), b); err != nil {
		return path, err
	}
	return path, prune(dir, path)
}

// prune removes the oldest per-report files, never the one just written.
func prune(dir, keep string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type item struct {
		path string
		mod  int64
	}
	var items []item
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || n == LastFile || !strings.HasSuffix(n, ".json") || strings.HasPrefix(n, ".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		items = append(items, item{filepath.Join(dir, n), info.ModTime().UnixNano()})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].mod != items[j].mod {
			return items[i].mod < items[j].mod
		}
		return items[i].path < items[j].path
	})
	for i := 0; len(items)-i > MaxSpoolFiles; i++ {
		if items[i].path == keep {
			continue
		}
		if err := os.Remove(items[i].path); err != nil {
			return err
		}
	}
	return nil
}

// ReadReport loads a spooled report, rejecting unknown fields, foreign
// schemas, and per-kind contract violations so `telemetry send` cannot be
// used to upload arbitrary files.
func ReadReport(path string) (Report, []byte, error) {
	var r Report
	b, err := os.ReadFile(path)
	if err != nil {
		return r, nil, err
	}
	if len(b) > MaxReportBytes*2 {
		return r, nil, fmt.Errorf("%s: %d bytes exceeds report bound", path, len(b))
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, nil, fmt.Errorf("%s: not a pleno-dlp report: %w", path, err)
	}
	if err := r.Validate(); err != nil {
		return r, nil, fmt.Errorf("%s: %w", path, err)
	}
	return r, b, nil
}
