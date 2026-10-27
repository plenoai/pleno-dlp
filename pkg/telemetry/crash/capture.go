package crash

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// EnvCrashDir overrides the raw runtime dump directory, independently of
	// EnvDir, which continues to control redacted telemetry reports.
	EnvCrashDir   = "PLENO_DLP_CRASH_DIR"
	EnvDisable    = "PLENO_DLP_CRASH_DISABLE"
	EnvReport     = "PLENO_DLP_CRASH_REPORT"
	maxSpoolFiles = 10
)

// CaptureConfig controls local runtime capture, independently of upload opt-in.
type CaptureConfig struct {
	Dir      string
	Disabled bool
}

// Dump contains raw runtime crash text. It may contain secrets; it is never
// uploaded through the redacted telemetry pipeline.
type Dump struct {
	Path string
	Data []byte
}

// Session owns the process-wide crash writer. Close it only after a normal
// return, never in a defer that would run during panic unwinding.
type Session struct {
	dir, path string
	file      *os.File
}

var capture struct {
	sync.Mutex
	session *Session
}

// DefaultDir resolves the raw dump spool under the user's cache directory.
func DefaultDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("crash: resolve user cache dir: %w", err)
	}
	return filepath.Join(base, "pleno-dlp", "crashes"), nil
}

func captureDir(dir string) (string, error) {
	if dir != "" {
		return dir, nil
	}
	if dir = os.Getenv(EnvCrashDir); dir != "" {
		return dir, nil
	}
	return DefaultDir()
}

// Install captures panics on every goroutine and runtime fatal errors using
// debug.SetCrashOutput (Go 1.23+). Failure leaves the CLI free to continue.
// Only one session may be installed at a time.
func Install(cfg CaptureConfig) (*Session, error) {
	if cfg.Disabled || os.Getenv(EnvDisable) == "1" {
		return &Session{}, nil
	}
	capture.Lock()
	defer capture.Unlock()
	if capture.session != nil {
		return nil, fmt.Errorf("crash: capture already installed")
	}
	dir, err := captureDir(cfg.Dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("crash: create spool dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("crash: secure spool dir: %w", err)
	}
	pruneDumps(dir, maxSpoolFiles)
	f, err := os.CreateTemp(dir, "crash-*.dump")
	if err != nil {
		return nil, fmt.Errorf("crash: create spool file: %w", err)
	}
	if err := debug.SetCrashOutput(f, debug.CrashOptions{}); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, fmt.Errorf("crash: install runtime crash writer: %w", err)
	}
	s := &Session{dir: dir, path: f.Name(), file: f}
	capture.session = s
	return s, nil
}

func (s *Session) Dir() string {
	if s == nil {
		return ""
	}
	return s.dir
}

func (s *Session) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Close releases the runtime's duplicated descriptor as well as our own,
// removes an empty spool, and preserves any recovered-panic report.
func (s *Session) Close() {
	if s == nil {
		return
	}
	capture.Lock()
	defer capture.Unlock()
	if s.file == nil {
		return
	}
	if capture.session == s {
		_ = debug.SetCrashOutput(nil, debug.CrashOptions{})
		capture.session = nil
	}
	info, err := s.file.Stat()
	_ = s.file.Close()
	s.file = nil
	if err == nil && info.Size() == 0 {
		_ = os.Remove(s.path)
	}
}

// Recover can be deferred by main to preserve a recovered panic locally before
// re-raising it. A re-panic lets the runtime write its complete fatal dump too.
func Recover() {
	v := recover()
	if v == nil {
		return
	}
	capture.Lock()
	if s := capture.session; s != nil && s.file != nil {
		_, _ = fmt.Fprintf(s.file, "recovered panic: %v\n\n%s\n", v, debug.Stack())
	}
	capture.Unlock()
	panic(v)
}

type dumpFile struct {
	path string
	mod  time.Time
}

func isDumpName(name string) bool {
	return strings.HasSuffix(name, ".dump") && (strings.HasPrefix(name, "crash-") || strings.HasPrefix(name, "panic-"))
}

func dumpFiles(dir string) ([]dumpFile, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("crash: read spool dir: %w", err)
	}
	var files []dumpFile
	for _, e := range entries {
		// Never follow symlinks or read special files from the spool.
		if !e.Type().IsRegular() || !isDumpName(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		// Empty files may belong to this process or another live scanner. Unlinking
		// them would silently discard that process's next crash.
		if info.Size() == 0 {
			continue
		}
		files = append(files, dumpFile{filepath.Join(dir, e.Name()), info.ModTime()})
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].mod.Equal(files[j].mod) {
			return files[i].path < files[j].path
		}
		return files[i].mod.Before(files[j].mod)
	})
	return files, nil
}

// Pending reads completed, non-empty dumps oldest first, leaving live empty
// spools alone. Files are retained until explicitly reported.
func Pending(dir string) ([]Dump, error) {
	dir, err := captureDir(dir)
	if err != nil {
		return nil, err
	}
	files, err := dumpFiles(dir)
	if err != nil {
		return nil, err
	}
	var dumps []Dump
	for _, f := range files {
		data, err := os.ReadFile(f.path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("crash: read spool: %w", err)
		}
		if len(data) != 0 {
			dumps = append(dumps, Dump{f.path, data})
		}
	}
	return dumps, nil
}

// ReportPending writes raw dumps to w and deletes only successfully reported
// files. Callers must explicitly opt into reading potentially sensitive text.
func ReportPending(dir string, w io.Writer) (int, error) {
	dumps, err := Pending(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, d := range dumps {
		if _, err := fmt.Fprintf(w, "--- crash report %s ---\n", d.Path); err != nil {
			return n, err
		}
		written, err := w.Write(d.Data)
		if err != nil {
			return n, err
		}
		if written != len(d.Data) {
			return n, io.ErrShortWrite
		}
		if d.Data[len(d.Data)-1] != '\n' {
			if _, err := fmt.Fprintln(w); err != nil {
				return n, err
			}
		}
		if err := os.Remove(d.Path); err != nil && !os.IsNotExist(err) {
			return n, err
		}
		n++
	}
	return n, nil
}

func pruneDumps(dir string, limit int) {
	files, err := dumpFiles(dir)
	if err != nil || limit <= 0 {
		return
	}
	for _, f := range files[:max(0, len(files)-limit)] {
		_ = os.Remove(f.path)
	}
}
