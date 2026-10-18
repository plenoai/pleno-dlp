package engine

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// TestLineContract_DataFirstByteIsReportedLine enforces the shared contract
// documented in pkg/sources/sources.go: a line-bearing source sets Line to the
// 1-based line of Chunk.Data[0], and the engine reports a finding on Data[0] at
// exactly that line. Every line-bearing metadata type must satisfy this, so a
// source that prepends unchanged context cannot silently shift findings.
func TestLineContract_DataFirstByteIsReportedLine(t *testing.T) {
	const base = 7
	data := []byte("L07\nL08\nL09\nSECRET\n")

	cases := []struct {
		name string
		set  func(*sources.Metadata, int)
		get  func(sources.Metadata) int
	}{
		{
			name: "filesystem",
			set:  func(m *sources.Metadata, line int) { m.Filesystem = &sources.FilesystemMeta{Path: "f", Line: line} },
			get:  func(m sources.Metadata) int { return m.Filesystem.Line },
		},
		{
			name: "git",
			set:  func(m *sources.Metadata, line int) { m.Git = &sources.GitMeta{File: "f", Line: line} },
			get:  func(m sources.Metadata) int { return m.Git.Line },
		},
		{
			name: "github",
			set:  func(m *sources.Metadata, line int) { m.GitHub = &sources.GitHubMeta{File: "f", Line: line} },
			get:  func(m sources.Metadata) int { return m.GitHub.Line },
		},
		{
			name: "forge",
			set:  func(m *sources.Metadata, line int) { m.Forge = &sources.ForgeMeta{File: "f", Line: line} },
			get:  func(m sources.Metadata) int { return m.Forge.Line },
		},
		{
			name: "sqldump",
			set:  func(m *sources.Metadata, line int) { m.SQLDump = &sources.SQLDumpMeta{File: "f", Line: line} },
			get:  func(m sources.Metadata) int { return m.SQLDump.Line },
		},
		{
			name: "dockerimage",
			set:  func(m *sources.Metadata, line int) { m.DockerImage = &sources.DockerImageMeta{File: "f", Line: line} },
			get:  func(m sources.Metadata) int { return m.DockerImage.Line },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var md sources.Metadata
			tc.set(&md, base)
			c := &sources.Chunk{Data: data, SourceMetadata: md}

			if !hasSourceLine(c) {
				t.Fatalf("%s: hasSourceLine = false for a line-bearing chunk", tc.name)
			}
			if got := sourceLine(c); got != base {
				t.Fatalf("%s: sourceLine = %d, want %d", tc.name, got, base)
			}

			// A match on Data[0] is the anchor itself.
			first := chunkWithMatchLine(c, []byte("L07"))
			if got := tc.get(first.SourceMetadata); got != base {
				t.Fatalf("%s: finding on Data[0] line = %d, want %d", tc.name, got, base)
			}

			// A match three lines into the window keeps the relative offset.
			third := chunkWithMatchLine(c, []byte("SECRET"))
			if got := tc.get(third.SourceMetadata); got != base+3 {
				t.Fatalf("%s: finding at window offset 3 line = %d, want %d", tc.name, got, base+3)
			}

			// The shared source chunk must not be mutated by per-finding rewrites.
			if got := tc.get(c.SourceMetadata); got != base {
				t.Fatalf("%s: source chunk line mutated to %d, want %d", tc.name, got, base)
			}
		})
	}
}
