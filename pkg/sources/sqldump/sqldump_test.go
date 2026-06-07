package sqldump

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func writeDump(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func collect(t *testing.T, path string, opts ...func(*Config)) []*sources.Chunk {
	t.Helper()
	cfg := Config{Paths: []string{path}, ChunkLineCount: 10}
	for _, o := range opts {
		o(&cfg)
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	src := &Source{}
	if err := src.Init(context.Background(), "test", 0, 0, false, cfgJSON, 1); err != nil {
		t.Fatal(err)
	}
	ch := make(chan *sources.Chunk, 100)
	if err := src.Chunks(context.Background(), ch); err != nil {
		t.Fatal(err)
	}
	close(ch)
	var out []*sources.Chunk
	for c := range ch {
		out = append(out, c)
	}
	return out
}

const mysqlDump = `-- MySQL dump 10.13  Distrib 8.0.33
--
-- Host: mydb.abc123.us-east-1.rds.amazonaws.com
-- Database: myapp

USE ` + "`myapp`" + `;

CREATE TABLE ` + "`users`" + ` (
  id int NOT NULL,
  email varchar(255),
  api_key varchar(255)
);

INSERT INTO ` + "`users`" + ` VALUES (1,'admin@example.com','AKIAIOSFODNN7EXAMPLE');
INSERT INTO ` + "`users`" + ` VALUES (2,'bob@example.com','sk_live_abc123def456ghi789');

CREATE TABLE ` + "`config`" + ` (
  key_name varchar(255),
  value text
);

INSERT INTO ` + "`config`" + ` VALUES ('aws_secret','wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
INSERT INTO ` + "`config`" + ` VALUES ('db_host','localhost');
`

func TestMySQLDump(t *testing.T) {
	dir := t.TempDir()
	path := writeDump(t, dir, "myapp.sql", mysqlDump)
	chunks := collect(t, path)

	if len(chunks) == 0 {
		t.Fatal("expected at least one chunk")
	}

	var allData string
	for _, c := range chunks {
		allData += string(c.Data)
		if c.SourceMetadata.SQLDump == nil {
			t.Fatal("expected SQLDump metadata")
		}
		if c.SourceMetadata.SQLDump.Format != "mysql" {
			t.Errorf("expected format=mysql, got %q", c.SourceMetadata.SQLDump.Format)
		}
	}

	for _, want := range []string{
		"AKIAIOSFODNN7EXAMPLE",
		"sk_live_abc123def456ghi789",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	} {
		if !strings.Contains(allData, want) {
			t.Errorf("chunk data missing %q", want)
		}
	}
}

const pgDump = `--
-- PostgreSQL database dump
--

\connect myapp

CREATE TABLE public.credentials (
    id integer NOT NULL,
    provider text,
    token text
);

COPY public.credentials (id, provider, token) FROM stdin;
1	github	ghp_ABCDEFghijklmnopqrstuvwxyz123456
2	stripe	sk_test_4eC39HqLyjWDarjtT1zdp7dc
\.

INSERT INTO public.settings (key, val) VALUES ('smtp_password', 'p@ssw0rd_secret');
`

func TestPostgresDump(t *testing.T) {
	dir := t.TempDir()
	path := writeDump(t, dir, "myapp.pgsql", pgDump)
	chunks := collect(t, path)

	if len(chunks) == 0 {
		t.Fatal("expected at least one chunk")
	}

	var allData string
	for _, c := range chunks {
		allData += string(c.Data)
		if c.SourceMetadata.SQLDump == nil {
			t.Fatal("expected SQLDump metadata")
		}
	}

	for _, want := range []string{
		"ghp_ABCDEFghijklmnopqrstuvwxyz123456",
		"sk_test_4eC39HqLyjWDarjtT1zdp7dc",
		"p@ssw0rd_secret",
	} {
		if !strings.Contains(allData, want) {
			t.Errorf("chunk data missing %q", want)
		}
	}
}

const sqliteDump = `BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS api_tokens (
  id integer PRIMARY KEY,
  name text,
  token text
);
INSERT INTO api_tokens VALUES(1,'deploy','xoxb-1234567890-abcdef');
INSERT INTO api_tokens VALUES(2,'monitor','rk_live_abc123XYZ');
COMMIT;
`

func TestSQLiteDump(t *testing.T) {
	dir := t.TempDir()
	path := writeDump(t, dir, "app.sqlite3", sqliteDump)
	chunks := collect(t, path)

	if len(chunks) == 0 {
		t.Fatal("expected at least one chunk")
	}

	var allData string
	for _, c := range chunks {
		allData += string(c.Data)
		if c.SourceMetadata.SQLDump == nil {
			t.Fatal("expected SQLDump metadata")
		}
		if c.SourceMetadata.SQLDump.Format != "sqlite" {
			t.Errorf("expected format=sqlite, got %q", c.SourceMetadata.SQLDump.Format)
		}
	}

	for _, want := range []string{"xoxb-1234567890-abcdef", "rk_live_abc123XYZ"} {
		if !strings.Contains(allData, want) {
			t.Errorf("chunk data missing %q", want)
		}
	}
}

func TestTableFilter(t *testing.T) {
	dir := t.TempDir()
	path := writeDump(t, dir, "filtered.sql", mysqlDump)

	t.Run("include", func(t *testing.T) {
		chunks := collect(t, path, func(c *Config) {
			c.IncludeTables = []string{"config"}
		})
		var allData string
		for _, c := range chunks {
			allData += string(c.Data)
		}
		if strings.Contains(allData, "AKIAIOSFODNN7EXAMPLE") {
			t.Error("users table data should be excluded")
		}
		if !strings.Contains(allData, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") {
			t.Error("config table data should be included")
		}
	})

	t.Run("exclude", func(t *testing.T) {
		chunks := collect(t, path, func(c *Config) {
			c.ExcludeTables = []string{"users"}
		})
		var allData string
		for _, c := range chunks {
			allData += string(c.Data)
		}
		if strings.Contains(allData, "AKIAIOSFODNN7EXAMPLE") {
			t.Error("users table data should be excluded")
		}
		if !strings.Contains(allData, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") {
			t.Error("config table data should be included")
		}
	})
}

func TestDatabaseContext(t *testing.T) {
	dir := t.TempDir()
	path := writeDump(t, dir, "db.sql", mysqlDump)
	chunks := collect(t, path)

	for _, c := range chunks {
		if c.SourceMetadata.SQLDump.Database != "myapp" {
			t.Errorf("expected database=myapp, got %q", c.SourceMetadata.SQLDump.Database)
		}
	}
}

func TestCommentWithSecret(t *testing.T) {
	dump := `-- MySQL dump
-- password: hunter2_secret_key
INSERT INTO t VALUES (1);
`
	dir := t.TempDir()
	path := writeDump(t, dir, "comment.sql", dump)
	chunks := collect(t, path)

	var allData string
	for _, c := range chunks {
		allData += string(c.Data)
	}
	if !strings.Contains(allData, "hunter2_secret_key") {
		t.Error("comment containing password keyword should be emitted")
	}
}

func TestFormatDetection(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		content string
		want    string
	}{
		{"mysql header", "dump.sql", "-- MySQL dump 10.13\nINSERT INTO t VALUES (1);", "mysql"},
		{"pg header", "dump.sql", "-- PostgreSQL database dump\n\\connect db\n", "postgres"},
		{"sqlite pattern", "dump.sql", "BEGIN TRANSACTION;\nCREATE TABLE t(id int);\n", "sqlite"},
		{"mysql ext", "dump.mysql", "INSERT INTO t VALUES (1);", "mysql"},
		{"pg ext", "dump.pgsql", "INSERT INTO t VALUES (1);", "postgres"},
		{"sqlite ext", "dump.sqlite3", "INSERT INTO t VALUES (1);", "sqlite"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeDump(t, dir, tt.file, tt.content)

			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			got := detectFormat(path, f)
			if got != tt.want {
				t.Errorf("detectFormat(%q) = %q, want %q", tt.file, got, tt.want)
			}
		})
	}
}

func TestExtractTableName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"`users` VALUES", "users"},
		{"`mydb`.`users` VALUES", "users"},
		{`"public"."credentials" (id)`, "credentials"},
		{"users VALUES", "users"},
		{"public.users VALUES", "users"},
		{"public.credentials (id, name) FROM stdin;", "credentials"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractTableName(tt.input)
			if got != tt.want {
				t.Errorf("extractTableName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestContextCancellation(t *testing.T) {
	dir := t.TempDir()
	path := writeDump(t, dir, "big.sql", strings.Repeat("INSERT INTO t VALUES ('data');\n", 1000))

	cfg, _ := json.Marshal(Config{Paths: []string{path}, ChunkLineCount: 1})
	src := &Source{}
	if err := src.Init(context.Background(), "test", 0, 0, false, cfg, 1); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan *sources.Chunk, 1)
	cancel()

	err := src.Chunks(ctx, ch)
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("expected context canceled error, got %v", err)
	}
}

func TestInitValidation(t *testing.T) {
	t.Run("no paths", func(t *testing.T) {
		src := &Source{}
		cfg, _ := json.Marshal(Config{})
		err := src.Init(context.Background(), "test", 0, 0, false, cfg, 1)
		if err == nil || !strings.Contains(err.Error(), "at least one path") {
			t.Errorf("expected path error, got %v", err)
		}
	})

	t.Run("nonexistent path", func(t *testing.T) {
		src := &Source{}
		cfg, _ := json.Marshal(Config{Paths: []string{"/nonexistent/dump.sql"}})
		err := src.Init(context.Background(), "test", 0, 0, false, cfg, 1)
		if err == nil {
			t.Error("expected error for nonexistent path")
		}
	})

	t.Run("bad format", func(t *testing.T) {
		dir := t.TempDir()
		p := writeDump(t, dir, "f.sql", "data")
		src := &Source{}
		cfg, _ := json.Marshal(Config{Paths: []string{p}, Format: "oracle"})
		err := src.Init(context.Background(), "test", 0, 0, false, cfg, 1)
		if err == nil || !strings.Contains(err.Error(), "unknown format") {
			t.Errorf("expected format error, got %v", err)
		}
	})

	t.Run("directory path", func(t *testing.T) {
		dir := t.TempDir()
		src := &Source{}
		cfg, _ := json.Marshal(Config{Paths: []string{dir}})
		err := src.Init(context.Background(), "test", 0, 0, false, cfg, 1)
		if err == nil || !strings.Contains(err.Error(), "directory") {
			t.Errorf("expected directory error, got %v", err)
		}
	})
}

func TestResourceFingerprint(t *testing.T) {
	dir := t.TempDir()
	path := writeDump(t, dir, "fp.sql", "INSERT INTO t VALUES (1);")

	cfg, _ := json.Marshal(Config{Paths: []string{path}})
	src := &Source{}
	if err := src.Init(context.Background(), "test", 0, 0, false, cfg, 1); err != nil {
		t.Fatal(err)
	}

	fp1, err := src.ResourceFingerprint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fp1 == "" {
		t.Error("expected non-empty fingerprint")
	}

	fp2, err := src.ResourceFingerprint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 {
		t.Error("fingerprint should be stable")
	}
}

func TestSourceType(t *testing.T) {
	src := &Source{}
	if src.Type() != sources.SourceSQLDump {
		t.Errorf("expected SourceSQLDump, got %v", src.Type())
	}
}

func TestChunkLineCount(t *testing.T) {
	dump := strings.Repeat("INSERT INTO t VALUES ('v');\n", 25)
	dir := t.TempDir()
	path := writeDump(t, dir, "lines.sql", "-- MySQL dump\n"+dump)
	chunks := collect(t, path, func(c *Config) {
		c.ChunkLineCount = 10
	})

	if len(chunks) != 3 {
		t.Errorf("expected 3 chunks (10+10+5), got %d", len(chunks))
	}
}
