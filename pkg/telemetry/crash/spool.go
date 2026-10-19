package crash

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MaxSpoolFiles caps retained per-crash files; last.json is not counted.
const MaxSpoolFiles = 20

// LastFile is the name of the most recent report in the spool.
const LastFile = "last.json"

// Spool writes the report to <dir>/<fingerprint>-<unix>.json and
// <dir>/last.json, then prunes the oldest files beyond MaxSpoolFiles.
// It returns the per-crash path.
func Spool(dir string, r Report) (string, error) {
	b, err := Encode(r)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("%s-%d.json", r.Fingerprint, r.CreatedAt.Unix()))
	if err := writePrivate(dir, path, b); err != nil {
		return "", err
	}
	if err := writePrivate(dir, filepath.Join(dir, LastFile), b); err != nil {
		return path, err
	}
	return path, prune(dir, path)
}

// prune removes the oldest per-crash files, never the one just written.
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

// ReadReport loads a spooled report, rejecting unknown fields and foreign
// schemas so `telemetry send` cannot be used to upload arbitrary files.
func ReadReport(path string) (Report, []byte, error) {
	var r Report
	b, err := os.ReadFile(path)
	if err != nil {
		return r, nil, err
	}
	if len(b) > MaxReportBytes*2 {
		return r, nil, fmt.Errorf("%s: %d bytes exceeds crash report bound", path, len(b))
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, nil, fmt.Errorf("%s: not a crash report: %w", path, err)
	}
	if r.Schema != Schema {
		return r, nil, fmt.Errorf("%s: schema %q, want %q", path, r.Schema, Schema)
	}
	return r, b, nil
}

// WriteFile writes r to an operator-named path for a local --crash-report. It
// uses the same encoding as Spool, so the file is byte-identical to what
// `telemetry show-last` prints for the same report; it creates parent
// directories 0700, writes the file 0600, and never sends anything.
func WriteFile(path string, r Report) error {
	b, err := Encode(r)
	if err != nil {
		return fmt.Errorf("crash-report: encode: %w", err)
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("crash-report: create %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("crash-report: write %s: %w", path, err)
	}
	return nil
}
