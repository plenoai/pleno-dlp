package feedback

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MaxSpoolFiles caps retained per-feedback files; last.json is not counted.
const MaxSpoolFiles = 20

// LastFile is the name of the most recent feedback report in the spool.
const LastFile = "last.json"

// Spool writes the report to <dir>/<fingerprint>-<unix>.json and
// <dir>/last.json, then prunes the oldest files beyond MaxSpoolFiles. It
// returns the per-feedback path. Sent or not, a local copy always remains.
func Spool(dir string, r Report) (string, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	b = append(b, '\n')
	path := filepath.Join(dir, fmt.Sprintf("%s-%d.json", r.Fingerprint, r.CreatedAt.Unix()))
	if err := writePrivate(dir, path, b); err != nil {
		return "", err
	}
	if err := writePrivate(dir, filepath.Join(dir, LastFile), b); err != nil {
		return path, err
	}
	return path, prune(dir, path)
}

// prune removes the oldest per-feedback files, never the one just written.
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

// ReadReport loads a spooled feedback report, rejecting unknown fields and
// foreign schemas so a spooled file cannot be mistaken for another report
// kind or carry fields outside the allowlist.
func ReadReport(path string) (Report, []byte, error) {
	var r Report
	b, err := os.ReadFile(path)
	if err != nil {
		return r, nil, err
	}
	if len(b) > MaxReportBytes*2 {
		return r, nil, fmt.Errorf("%s: %d bytes exceeds feedback report bound", path, len(b))
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, nil, fmt.Errorf("%s: not a feedback report: %w", path, err)
	}
	if r.Schema != Schema {
		return r, nil, fmt.Errorf("%s: schema %q, want %q", path, r.Schema, Schema)
	}
	return r, b, nil
}

// writePrivate atomically writes data with 0600 under a 0700 directory.
func writePrivate(dir, path string, data []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
