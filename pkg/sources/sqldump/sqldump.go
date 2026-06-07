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

	for _, path := range s.cfg.Paths {
		path := path
		sem <- struct{}{}
		g.Go(func() error {
			defer func() { <-sem }()
			return s.scanFile(gctx, path, ch)
		})
	}
	return g.Wait()
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

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), s.cfg.MaxLineBytes)

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

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		lineNum++
		line := scanner.Text()

		p.trackContext(line)

		if !p.isDataLine(line) {
			continue
		}
		if !p.tableAllowed() {
			continue
		}

		if lineCount == 0 {
			chunkStartLine = lineNum
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
		lineCount++

		if lineCount >= s.cfg.ChunkLineCount {
			if err := s.emitChunk(ctx, ch, abs, p, buf.Bytes(), chunkStartLine, format); err != nil {
				return err
			}
			buf.Reset()
			lineCount = 0
		}
	}

	if lineCount > 0 {
		if err := s.emitChunk(ctx, ch, abs, p, buf.Bytes(), chunkStartLine, format); err != nil {
			return err
		}
	}

	return scanner.Err()
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
		Verify: s.verify,
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
		raw := upper[13:]
		if strings.HasPrefix(raw, "IF NOT EXISTS ") {
			raw = raw[14:]
		}
		p.table = extractTableName(line[len(line)-len(strings.TrimLeft(line, " \t"))+13:])
		_ = raw
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
