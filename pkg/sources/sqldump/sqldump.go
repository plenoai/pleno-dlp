// Package sqldump scans SQL dump files for secrets. It streams dump files
// line-by-line, tracking database/table context from DDL statements and
// emitting data-carrying lines (INSERT values, COPY blocks, comments) as
// chunks. Supports mysqldump, pg_dump, and sqlite3 .dump formats.
package sqldump

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/sources"
	"golang.org/x/sync/errgroup"
)

const defaultMaxSizeBytes int64 = 512 * 1024 * 1024 // 512 MiB — dumps are large

func init() {
	sources.Register(sources.SourceSQLDump, func() sources.Source { return &Source{} })
}

type Config struct {
	Paths          []string `json:"paths"`
	Format         string   `json:"format"` // "auto", "mysql", "postgres", "sqlite"
	MaxSizeBytes   int64    `json:"max_size_bytes"`
	IncludeTables  []string `json:"include_tables,omitempty"`
	ExcludeTables  []string `json:"exclude_tables,omitempty"`
	MaxLineBytes   int      `json:"max_line_bytes"`
	ChunkLineCount int      `json:"chunk_line_count"`
}

type Source struct {
	name        string
	jobID       int64
	sourceID    int64
	verify      bool
	concurrency int
	cfg         Config

	hasPreviousState bool
	previousState    *incrementalState
	nextState        *incrementalState
}

type incrementalState struct {
	Version int                             `json:"version"`
	Files   map[string]fileIncrementalState `json:"files"`
}

type fileIncrementalState struct {
	Size    int64 `json:"size"`
	ModTime int64 `json:"mod_time"`
}

func (s *Source) Type() sources.SourceType { return sources.SourceSQLDump }

func (s *Source) Init(_ context.Context, name string, jobID, sourceID int64, verify bool, config []byte, concurrency int) error {
	var cfg Config
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return fmt.Errorf("sqldump: invalid config json: %w", err)
		}
	}
	if len(cfg.Paths) == 0 {
		return errors.New("sqldump: config.paths must contain at least one path")
	}
	for _, p := range cfg.Paths {
		info, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("sqldump: path %q: %w", p, err)
		}
		if info.IsDir() {
			return fmt.Errorf("sqldump: path %q is a directory; provide dump files directly", p)
		}
	}
	switch cfg.Format {
	case "", "auto":
		cfg.Format = "auto"
	case "mysql", "postgres", "sqlite":
	default:
		return fmt.Errorf("sqldump: unknown format %q (valid: auto, mysql, postgres, sqlite)", cfg.Format)
	}
	if cfg.MaxSizeBytes <= 0 {
		cfg.MaxSizeBytes = defaultMaxSizeBytes
	}
	if cfg.MaxLineBytes <= 0 {
		cfg.MaxLineBytes = 4 * 1024 * 1024 // 4 MiB per line
	}
	if cfg.ChunkLineCount <= 0 {
		cfg.ChunkLineCount = 50
	}
	if concurrency <= 0 {
		concurrency = 1
	}
	s.name = name
	s.jobID = jobID
	s.sourceID = sourceID
	s.verify = verify
	s.concurrency = concurrency
	s.cfg = cfg
	return nil
}

func (s *Source) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	g, gctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, s.concurrency)
	s.nextState = &incrementalState{Version: 1, Files: map[string]fileIncrementalState{}}

	for _, path := range s.cfg.Paths {
		path := path
		abs, state, ok := s.fileState(path)
		if ok {
			s.nextState.Files[abs] = state
			if s.fileUnchanged(abs, state) {
				continue
			}
		}
		sem <- struct{}{}
		g.Go(func() error {
			defer func() { <-sem }()
			return s.scanFile(gctx, path, ch)
		})
	}
	return g.Wait()
}

func (s *Source) SetIncrementalState(previous json.RawMessage) error {
	s.hasPreviousState = false
	s.previousState = nil
	s.nextState = nil
	if len(previous) == 0 || string(previous) == "null" {
		return nil
	}
	var state incrementalState
	if err := json.Unmarshal(previous, &state); err != nil {
		return err
	}
	if state.Files == nil {
		state.Files = map[string]fileIncrementalState{}
	}
	s.hasPreviousState = true
	s.previousState = &state
	return nil
}

func (s *Source) IncrementalState() json.RawMessage {
	if s.nextState == nil {
		return nil
	}
	data, err := json.Marshal(s.nextState)
	if err != nil {
		return nil
	}
	return data
}

func (s *Source) fileUnchanged(path string, current fileIncrementalState) bool {
	if !s.hasPreviousState || s.previousState == nil {
		return false
	}
	prev, ok := s.previousState.Files[path]
	return ok && prev == current
}

func (s *Source) ResourceFingerprint(_ context.Context) (string, error) {
	h := sha256.New()
	writeHash(h, "sqldump-v1")
	for _, p := range s.cfg.Paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		writeHash(h, abs)
		info, err := os.Stat(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return "", err
		}
		writeHash(h, fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano()))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Source) scanFile(ctx context.Context, path string, ch chan<- *sources.Chunk) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsPermission(err) || errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return nil
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil
	}
	if info.Size() > s.cfg.MaxSizeBytes {
		return nil
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}

	format := s.cfg.Format
	if format == "auto" {
		format = detectFormat(path, f)
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil
		}
	}

	// bufio.Scanner aborts the whole file on the first line longer than its
	// buffer (bufio.ErrTooLong), which would drop every secret after an
	// oversized line. --max-line-bytes documents "longer lines are skipped",
	// so read with a bufio.Reader that skips the oversized line and continues.
	reader := bufio.NewReaderSize(f, 64*1024)

	p := &parser{
		format:  format,
		file:    abs,
		include: s.cfg.IncludeTables,
		exclude: s.cfg.ExcludeTables,
	}

	var buf bytes.Buffer
	var chunkStartLine int
	lineCount := 0
	lineNum := 0
	skippedLines := 0

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, skipped, err := readLine(reader, s.cfg.MaxLineBytes)
		if skipped {
			// The oversized line is skipped whole rather than scanned in
			// part, so a secret split across the cutoff isn't half-matched.
			// lineNum still advances so later line numbers stay accurate.
			lineNum++
			skippedLines++
		} else if len(line) > 0 || err == nil {
			lineNum++
			lineStr := string(line)
			p.trackContext(lineStr)
			if p.isDataLine(lineStr) && p.tableAllowed() {
				if lineCount == 0 {
					chunkStartLine = lineNum
				}
				buf.WriteString(lineStr)
				buf.WriteByte('\n')
				lineCount++

				if lineCount >= s.cfg.ChunkLineCount {
					if emitErr := s.emitChunk(ctx, ch, abs, p, buf.Bytes(), chunkStartLine, format); emitErr != nil {
						return emitErr
					}
					buf.Reset()
					lineCount = 0
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}

	if lineCount > 0 {
		if err := s.emitChunk(ctx, ch, abs, p, buf.Bytes(), chunkStartLine, format); err != nil {
			return err
		}
	}

	if skippedLines > 0 {
		sqldumpWarnf("sqldump: skipped %d line(s) over --max-line-bytes=%d in %s\n",
			skippedLines, s.cfg.MaxLineBytes, abs)
	}

	return nil
}

// readLine reads the next newline-terminated line from r, returning it with the
// trailing CR/LF stripped. A line longer than max bytes is drained to its end
// and reported with skipped=true and a nil line, so the caller skips it and
// keeps scanning subsequent lines. The final line without a trailing newline is
// returned alongside io.EOF.
func readLine(r *bufio.Reader, max int) (line []byte, skipped bool, err error) {
	var full []byte
	n := 0 // content bytes seen so far, excluding the terminating newline
	for {
		frag, e := r.ReadSlice('\n')
		content := frag
		if e == nil && len(content) > 0 && content[len(content)-1] == '\n' {
			content = content[:len(content)-1]
		}
		n += len(content)
		if !skipped {
			if n > max {
				skipped = true
				full = nil
			} else {
				full = append(full, frag...)
			}
		}
		if e == bufio.ErrBufferFull {
			continue
		}
		if skipped {
			return nil, true, e
		}
		return trimEOL(full), false, e
	}
}

// trimEOL drops a single trailing "\n" or "\r\n" from a line.
func trimEOL(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
		if n := len(b); n > 0 && b[n-1] == '\r' {
			b = b[:n-1]
		}
	}
	return b
}

// sqldumpWarnf reports non-fatal scan degradation (e.g. skipped oversized
// lines) to stderr. It is a package var so tests can capture the warnings.
var sqldumpWarnf = func(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
}

func (s *Source) emitChunk(ctx context.Context, ch chan<- *sources.Chunk, file string, p *parser, data []byte, line int, format string) error {
	chunk := &sources.Chunk{
		SourceID:   s.sourceID,
		SourceType: sources.SourceSQLDump,
		SourceName: s.name,
		Data:       append([]byte(nil), data...),
		SourceMetadata: sources.Metadata{
			SQLDump: &sources.SQLDumpMeta{
				File:     file,
				Database: p.database,
				Table:    p.table,
				Line:     line,
				Format:   format,
			},
		},
	}
	select {
	case ch <- chunk:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type parser struct {
	format   string
	file     string
	database string
	table    string
	inCopy   bool // postgres COPY ... FROM stdin block
	include  []string
	exclude  []string
}

func (p *parser) trackContext(line string) {
	upper := strings.ToUpper(strings.TrimSpace(line))
	switch p.format {
	case "mysql":
		p.trackMySQL(line, upper)
	case "postgres":
		p.trackPostgres(line, upper)
	case "sqlite":
		p.trackSQLite(line, upper)
	default:
		p.trackMySQL(line, upper)
		p.trackPostgres(line, upper)
	}
}

func (p *parser) trackMySQL(line, upper string) {
	switch {
	case strings.HasPrefix(upper, "USE "):
		p.database = extractUnquoted(line[4:])
	case strings.HasPrefix(upper, "INSERT INTO "):
		p.table = extractTableName(line[12:])
	case strings.HasPrefix(upper, "CREATE TABLE "):
		p.table = extractTableName(line[len(line)-len(strings.TrimLeft(line, " \t"))+13:])
	}
}

func (p *parser) trackPostgres(line, upper string) {
	switch {
	case strings.HasPrefix(upper, "\\CONNECT ") || strings.HasPrefix(upper, "\\C "):
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			p.database = parts[1]
		}
	case strings.HasPrefix(upper, "COPY "):
		p.table = extractTableName(line[5:])
		if strings.HasSuffix(upper, "FROM STDIN;") || strings.HasSuffix(upper, "FROM STDIN") {
			p.inCopy = true
		}
	case strings.HasPrefix(upper, "INSERT INTO "):
		p.table = extractTableName(line[12:])
	case p.inCopy && strings.TrimSpace(line) == "\\.":
		p.inCopy = false
	}
}

func (p *parser) trackSQLite(line, upper string) {
	switch {
	case strings.HasPrefix(upper, "INSERT INTO "):
		p.table = extractTableName(line[12:])
	case strings.HasPrefix(upper, "CREATE TABLE "):
		raw := upper[13:]
		if strings.HasPrefix(raw, "IF NOT EXISTS ") {
			p.table = extractTableName(line[27:])
		} else {
			p.table = extractTableName(line[13:])
		}
	}
}

func (p *parser) isDataLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}

	if p.inCopy {
		return trimmed != "\\."
	}

	upper := strings.ToUpper(trimmed)

	if strings.HasPrefix(upper, "INSERT ") {
		return true
	}

	if strings.HasPrefix(trimmed, "--") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") {
		return containsPotentialSecret(trimmed)
	}

	if strings.HasPrefix(upper, "COPY ") && (strings.Contains(upper, "FROM STDIN") || strings.Contains(upper, "FROM PROGRAM")) {
		return false
	}

	return false
}

func (p *parser) tableAllowed() bool {
	if p.table == "" {
		return true
	}
	lower := strings.ToLower(p.table)
	if len(p.include) > 0 {
		found := false
		for _, t := range p.include {
			if strings.EqualFold(t, lower) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, t := range p.exclude {
		if strings.EqualFold(t, lower) {
			return false
		}
	}
	return true
}

func containsPotentialSecret(comment string) bool {
	lower := strings.ToLower(comment)
	for _, kw := range []string{
		"password", "passwd", "secret", "token", "key", "api_key",
		"apikey", "auth", "credential", "private", "access_key",
	} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func extractTableName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	var name strings.Builder
	i := 0

	if s[0] == '`' || s[0] == '"' || s[0] == '[' {
		closer := closerFor(s[0])
		i++
		for i < len(s) && s[i] != closer {
			name.WriteByte(s[i])
			i++
		}
		if i < len(s) {
			i++
		}
		if i < len(s) && s[i] == '.' {
			i++
			return extractTableName(s[i:])
		}
		return name.String()
	}

	for i < len(s) && s[i] != ' ' && s[i] != '(' && s[i] != '\t' && s[i] != ';' {
		if s[i] == '.' {
			name.Reset()
			i++
			continue
		}
		name.WriteByte(s[i])
		i++
	}
	return name.String()
}

func closerFor(opener byte) byte {
	switch opener {
	case '`':
		return '`'
	case '"':
		return '"'
	case '[':
		return ']'
	}
	return opener
}

func extractUnquoted(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, ";")
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "`\"'")
	return s
}

func detectFormat(path string, r io.Reader) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".sql":
		// peek at content
	case ".mysql":
		return "mysql"
	case ".pgsql", ".psql":
		return "postgres"
	case ".sqlite", ".sqlite3":
		return "sqlite"
	}

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	if n == 0 {
		return "mysql"
	}
	content := string(buf[:n])
	upper := strings.ToUpper(content)

	switch {
	case strings.Contains(content, "-- MySQL dump") || strings.Contains(content, "mysqldump"):
		return "mysql"
	case strings.Contains(content, "-- PostgreSQL") || strings.Contains(upper, "\\CONNECT") || strings.Contains(content, "pg_dump"):
		return "postgres"
	case strings.Contains(content, "BEGIN TRANSACTION") && strings.Contains(upper, "CREATE TABLE"):
		return "sqlite"
	case strings.Contains(upper, "COPY ") && strings.Contains(upper, "FROM STDIN"):
		return "postgres"
	default:
		return "mysql"
	}
}

func writeHash(h hash.Hash, s string) {
	_, _ = h.Write([]byte(s))
	_, _ = h.Write([]byte{0})
}

var _ sources.Source = (*Source)(nil)
var _ sources.ResourceFingerprinter = (*Source)(nil)
var _ sources.IncrementalStateSource = (*Source)(nil)

func (s *Source) fileState(path string) (string, fileIncrementalState, bool) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() > s.cfg.MaxSizeBytes {
		return abs, fileIncrementalState{}, false
	}
	return abs, fileIncrementalState{
		Size:    info.Size(),
		ModTime: info.ModTime().UnixNano(),
	}, true
}
