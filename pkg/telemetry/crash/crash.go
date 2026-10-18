// Package crash captures process crashes for telemetry using the Go
// runtime's own crash writer instead of a re-exec supervisor.
//
// Background (issue #497 follow-up)
//
// Crash capture historically ran in one of two disjoint modes. With crash
// reports off (the default) only a panic on the main goroutine was
// observed, because a deferred crash.Recover in main was the only thing
// looking. A panic on any other goroutine, and any runtime fatal error
// (concurrent map writes, stack exhaustion, the deadlock detector), was
// lost. Turning reports on paid for a second process: the binary
// re-executed itself as a supervisor that inherited stderr, re-ran
// detector registration, and reconstructed crashes by parsing that stderr
// stream. That parser had to carry a 16-byte tail across reads and
// misread any non-zero exit that happened to print "panic:" as a crash
// (for example a hook exiting 2 on a finding).
//
// Go 1.23 added runtime/debug.SetCrashOutput, which points the runtime's
// own crash writer at a file descriptor the process already owns. One
// mechanism now covers every fatal path — panics on any goroutine and
// runtime fatals alike — in-process, with no second process, no detector
// re-registration, and no stderr parsing.
//
// This package wires that up. Install points the crash writer at a
// per-process spool file; a later run uses Pending (or ReportPending) to
// read dumps left behind by earlier runs.
//
// A dump is the runtime's own crash text (the same text that goes to
// stderr), so there is no format of our own to keep stable and no
// heuristics to tune.
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
	// EnvDir overrides the directory crash dumps are spooled to.
	EnvDir = "PLENO_DLP_CRASH_DIR"
	// EnvDisable, when set to "1", disables crash capture entirely.
	EnvDisable = "PLENO_DLP_CRASH_DISABLE"
	// EnvReport, when set to "1", surfaces and removes dumps left by
	// earlier crashes. Capture itself is always local and cheap; this
	// opt-in controls only whether old dumps are read back out.
	EnvReport = "PLENO_DLP_CRASH_REPORT"

	crashPrefix = "crash-"
	panicPrefix = "panic-"
	dumpSuffix  = ".dump"

	// maxSpoolFiles bounds how many dumps an earlier run's crashes may
	// leave behind. Install prunes the oldest first, so a crash loop
	// cannot fill the spool directory.
	maxSpoolFiles = 10
)

// setCrashOutput is the seam through which Install reaches the runtime.
// Production leaves it at debug.SetCrashOutput; tests replace it because
// the runtime allows the writer to be configured at most once per process.
var setCrashOutput = debug.SetCrashOutput

// Config controls a crash-capture session.
type Config struct {
	// Dir is where dumps are spooled. Empty resolves EnvDir, then
	// DefaultDir.
	Dir string
	// Disabled skips capture entirely: no directory is created and no
	// crash writer is installed.
	Disabled bool
}

// Dump is a crash report recovered from an earlier run.
type Dump struct {
	// Path is the spool file the dump was read from. It is removed once
	// the dump has been reported.
	Path string
	// Data is the raw crash text.
	Data []byte
}

// Session owns the process's open crash-output file. Call Close on a
// clean exit to delete the (empty) spool file.
type Session struct {
	dir  string
	path string
	file *os.File
	once sync.Once
}

// DefaultDir returns the crash spool directory used when neither Config.Dir
// nor EnvDir is set: <user cache dir>/pleno-dlp/crashes.
func DefaultDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("crash: resolve user cache dir: %w", err)
	}
	return filepath.Join(base, "pleno-dlp", "crashes"), nil
}

func resolveDir(cfg Config) (string, error) {
	if cfg.Dir != "" {
		return cfg.Dir, nil
	}
	if env := os.Getenv(EnvDir); env != "" {
		return env, nil
	}
	return DefaultDir()
}

// Install starts crash capture: it creates dir (mode 0700), prunes stale
// dumps, opens a fresh spool file, and points the runtime's crash writer
// at it. The returned Session must be Closed on a clean exit.
//
// Capture is best-effort and safe to leave installed for the whole
// process: unlike the old supervisor it does no work until the process
// actually crashes.
func Install(cfg Config) (*Session, error) {
	if cfg.Disabled || os.Getenv(EnvDisable) == "1" {
		return &Session{}, nil
	}
	dir, err := resolveDir(cfg)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("crash: create spool dir %s: %w", dir, err)
	}
	pruneDumps(dir, maxSpoolFiles)

	f, err := os.CreateTemp(dir, crashPrefix+"*"+dumpSuffix)
	if err != nil {
		return nil, fmt.Errorf("crash: create spool file: %w", err)
	}
	if err := setCrashOutput(f, debug.CrashOptions{}); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, fmt.Errorf("crash: install runtime crash writer: %w", err)
	}

	s := &Session{dir: dir, path: f.Name(), file: f}
	globalMu.Lock()
	global = s
	globalMu.Unlock()
	return s, nil
}

// Dir returns the spool directory the session writes to.
func (s *Session) Dir() string {
	if s == nil {
		return ""
	}
	return s.dir
}

// Path returns the spool file the runtime crash writer was pointed at, or
// "" when capture is disabled.
func (s *Session) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Close releases the session. If the process is exiting cleanly the spool
// file is empty, so it is deleted; a file the runtime filled in belongs to
// a crash and is left for Pending.
func (s *Session) Close() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		globalMu.Lock()
		if global == s {
			global = nil
		}
		globalMu.Unlock()

		if s.file != nil {
			_ = s.file.Close()
			s.file = nil
		}
		if s.path == "" {
			return
		}
		if fi, err := os.Stat(s.path); err == nil && fi.Size() == 0 {
			_ = os.Remove(s.path)
		}
	})
}

// global is the session installed by Install, consulted by Recover.
var (
	globalMu sync.Mutex
	global   *Session
)

// Recover is meant to be deferred once at the top of main. It is the only
// crash path the runtime's writer cannot see on its own: a panic on the
// main goroutine that something else might otherwise recover. Recover
// records the panic text into the installed session's spool file and then
// re-panics, so the process still exits non-zero and the runtime's crash
// writer records the fatal dump too. Without an installed session it
// simply re-panics, preserving the pre-existing behaviour.
func Recover() {
	r := recover()
	if r == nil {
		return
	}
	globalMu.Lock()
	s := global
	globalMu.Unlock()
	if s != nil && s.file != nil {
		writePanicReport(s.file, r)
	}
	panic(r)
}

// writePanicReport appends a recovered-panic report to f. It runs before
// the re-panic in Recover, so the runtime's dump follows it in the same
// spool file.
func writePanicReport(f *os.File, r any) {
	buf := make([]byte, 0, 1024)
	buf = append(buf, "recovered panic: "...)
	buf = fmt.Appendf(buf, "%v\n\n", r)
	buf = append(buf, debug.Stack()...)
	buf = append(buf, '\n')
	_, _ = f.Write(buf)
}

// Pending returns the non-empty crash dumps left behind by earlier runs,
// oldest first. Empty spool files (a clean run whose deferred Close did
// not get to run because it used os.Exit) are removed in passing.
func Pending(dir string) ([]Dump, error) {
	if dir == "" {
		var err error
		dir, err = resolveDir(Config{})
		if err != nil {
			return nil, err
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("crash: read spool dir %s: %w", dir, err)
	}

	var dumps []Dump
	for _, e := range entries {
		if e.IsDir() || !isDumpName(e.Name()) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("crash: read spool %s: %w", path, err)
		}
		if len(data) == 0 {
			_ = os.Remove(path)
			continue
		}
		dumps = append(dumps, Dump{Path: path, Data: data})
	}
	sort.Slice(dumps, func(i, j int) bool { return dumps[i].Path < dumps[j].Path })
	return dumps, nil
}

// ReportPending writes every pending dump to w under a header naming its
// file and removes the dumps it reported, returning how many it reported.
// It is the no-parsing replacement for the supervisor's stderr scraper:
// the bytes came straight from the runtime.
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
		if _, err := w.Write(d.Data); err != nil {
			return n, err
		}
		if d.Data[len(d.Data)-1] != '\n' {
			if _, err := fmt.Fprintln(w); err != nil {
				return n, err
			}
		}
		if err := os.Remove(d.Path); err != nil && !os.IsNotExist(err) {
			return n, fmt.Errorf("crash: remove reported dump %s: %w", d.Path, err)
		}
		n++
	}
	return n, nil
}

func isDumpName(name string) bool {
	if !strings.HasSuffix(name, dumpSuffix) {
		return false
	}
	return strings.HasPrefix(name, crashPrefix) || strings.HasPrefix(name, panicPrefix)
}

// pruneDumps keeps the newest max non-empty dump files in dir and removes
// the rest. Empty dumps are stale spool files from a prior run that exited
// via os.Exit (so its deferred Close never ran); they are always removed so
// they cannot evict a real crash dump. It only ever touches files this
// package created (crash-/panic- dumps). A zero max disables the count
// cap but still removes empty files.
func pruneDumps(dir string, max int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type dumpFile struct {
		path    string
		modTime time.Time
	}
	var files []dumpFile
	for _, e := range entries {
		if e.IsDir() || !isDumpName(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if info.Size() == 0 {
			_ = os.Remove(path)
			continue
		}
		files = append(files, dumpFile{path: path, modTime: info.ModTime()})
	}
	if max <= 0 || len(files) <= max {
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i].modTime.After(files[j].modTime) })
	for _, f := range files[max:] {
		_ = os.Remove(f.path)
	}
}
