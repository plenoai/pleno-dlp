package piidb

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestDeriveContainer_Filesystem(t *testing.T) {
	c := &sources.Chunk{
		SourceMetadata: sources.Metadata{
			Filesystem: &sources.FilesystemMeta{Path: "/data/exports/customers.csv", Line: 5},
		},
	}
	got := DeriveContainer(c)
	if got.Container != "/data/exports/customers.csv" {
		t.Errorf("Container = %q, want /data/exports/customers.csv", got.Container)
	}
	if got.Parent != "/data/exports" {
		t.Errorf("Parent = %q, want /data/exports", got.Parent)
	}
	if got.Extension != "csv" {
		t.Errorf("Extension = %q, want csv", got.Extension)
	}
}

func TestDeriveContainer_S3(t *testing.T) {
	c := &sources.Chunk{
		SourceMetadata: sources.Metadata{
			S3: &sources.S3Meta{Bucket: "prod-data", Key: "backups/2024/users.sql"},
		},
	}
	got := DeriveContainer(c)
	if got.Container != "s3://prod-data/backups/2024/users.sql" {
		t.Errorf("Container = %q", got.Container)
	}
	if got.Parent != "s3://prod-data/backups/2024" {
		t.Errorf("Parent = %q", got.Parent)
	}
	if got.Extension != "sql" {
		t.Errorf("Extension = %q, want sql", got.Extension)
	}
}

func TestDeriveContainer_GCS(t *testing.T) {
	c := &sources.Chunk{
		SourceMetadata: sources.Metadata{
			GCS: &sources.GCSMeta{Bucket: "analytics", Object: "exports/contacts.json"},
		},
	}
	got := DeriveContainer(c)
	if got.Container != "gs://analytics/exports/contacts.json" {
		t.Errorf("Container = %q", got.Container)
	}
	if got.Parent != "gs://analytics/exports" {
		t.Errorf("Parent = %q", got.Parent)
	}
	if got.Extension != "json" {
		t.Errorf("Extension = %q, want json", got.Extension)
	}
}

func TestDeriveContainer_Git(t *testing.T) {
	c := &sources.Chunk{
		SourceMetadata: sources.Metadata{
			Git: &sources.GitMeta{Repository: "myrepo", Commit: "abc123", File: "src/data.csv"},
		},
	}
	got := DeriveContainer(c)
	if got.Container != "myrepo@abc123:src/data.csv" {
		t.Errorf("Container = %q", got.Container)
	}
	if got.Parent != "myrepo:src" {
		t.Errorf("Parent = %q", got.Parent)
	}
	if got.Extension != "csv" {
		t.Errorf("Extension = %q, want csv", got.Extension)
	}
}

func TestDeriveContainer_GitHub(t *testing.T) {
	c := &sources.Chunk{
		SourceMetadata: sources.Metadata{
			GitHub: &sources.GitHubMeta{Repository: "org/repo", Commit: "def456", File: "db/seeds.sql"},
		},
	}
	got := DeriveContainer(c)
	if got.Container != "org/repo@def456:db/seeds.sql" {
		t.Errorf("Container = %q", got.Container)
	}
	if got.Parent != "org/repo:db" {
		t.Errorf("Parent = %q", got.Parent)
	}
	if got.Extension != "sql" {
		t.Errorf("Extension = %q, want sql", got.Extension)
	}
}

func TestDeriveContainer_Slack(t *testing.T) {
	c := &sources.Chunk{
		SourceMetadata: sources.Metadata{
			Slack: &sources.SlackMeta{Channel: "C12345", Timestamp: "1234567890.000100"},
		},
	}
	got := DeriveContainer(c)
	if got.Container != "C12345@1234567890.000100" {
		t.Errorf("Container = %q", got.Container)
	}
	if got.Parent != "C12345" {
		t.Errorf("Parent = %q", got.Parent)
	}
	if got.Extension != "" {
		t.Errorf("Extension = %q, want empty", got.Extension)
	}
}

func TestDeriveContainer_Jira(t *testing.T) {
	c := &sources.Chunk{
		SourceMetadata: sources.Metadata{
			Jira: &sources.JiraMeta{Project: "PROJ", IssueKey: "PROJ-123", Part: "description"},
		},
	}
	got := DeriveContainer(c)
	if got.Container != "PROJ/PROJ-123:description" {
		t.Errorf("Container = %q", got.Container)
	}
	if got.Parent != "PROJ" {
		t.Errorf("Parent = %q", got.Parent)
	}
}

func TestDeriveContainer_Confluence(t *testing.T) {
	c := &sources.Chunk{
		SourceMetadata: sources.Metadata{
			Confluence: &sources.ConfluenceMeta{SpaceKey: "ENG", PageID: "12345"},
		},
	}
	got := DeriveContainer(c)
	if got.Container != "ENG/12345" {
		t.Errorf("Container = %q", got.Container)
	}
	if got.Parent != "ENG" {
		t.Errorf("Parent = %q", got.Parent)
	}
}

func TestDeriveContainer_Notion(t *testing.T) {
	c := &sources.Chunk{
		SourceMetadata: sources.Metadata{
			Notion: &sources.NotionMeta{PageID: "abc-123", Database: "contacts-db", Part: "page"},
		},
	}
	got := DeriveContainer(c)
	if got.Container != "abc-123:page" {
		t.Errorf("Container = %q", got.Container)
	}
	if got.Parent != "contacts-db" {
		t.Errorf("Parent = %q", got.Parent)
	}
}

func TestDeriveContainer_Notion_NoDatabase(t *testing.T) {
	c := &sources.Chunk{
		SourceMetadata: sources.Metadata{
			Notion: &sources.NotionMeta{PageID: "abc-123", Part: "page"},
		},
	}
	got := DeriveContainer(c)
	if got.Parent != "abc-123" {
		t.Errorf("Parent = %q, want abc-123 (fallback to PageID)", got.Parent)
	}
}

func TestDeriveContainer_Bitbucket(t *testing.T) {
	c := &sources.Chunk{
		SourceMetadata: sources.Metadata{
			Bitbucket: &sources.BitbucketMeta{Workspace: "ws", Repo: "r", Commit: "c1", Path: "data/users.tsv"},
		},
	}
	got := DeriveContainer(c)
	if got.Container != "ws/r@c1:data/users.tsv" {
		t.Errorf("Container = %q", got.Container)
	}
	if got.Parent != "ws/r:data" {
		t.Errorf("Parent = %q", got.Parent)
	}
	if got.Extension != "tsv" {
		t.Errorf("Extension = %q, want tsv", got.Extension)
	}
}

func TestDeriveContainer_Forge(t *testing.T) {
	c := &sources.Chunk{
		SourceMetadata: sources.Metadata{
			Forge: &sources.ForgeMeta{Provider: "gitea", Repository: "org/repo", Commit: "x", File: "dump.sql"},
		},
	}
	got := DeriveContainer(c)
	if got.Container != "gitea/org/repo@x:dump.sql" {
		t.Errorf("Container = %q", got.Container)
	}
	if got.Parent != "gitea/org/repo:." {
		t.Errorf("Parent = %q", got.Parent)
	}
	if got.Extension != "sql" {
		t.Errorf("Extension = %q, want sql", got.Extension)
	}
}

func TestDeriveContainer_Stdin(t *testing.T) {
	c := &sources.Chunk{
		SourceMetadata: sources.Metadata{
			Stdin: &sources.StdinMeta{Label: "pipe-input"},
		},
	}
	got := DeriveContainer(c)
	if got.Container != "stdin:pipe-input" {
		t.Errorf("Container = %q", got.Container)
	}
	if got.Parent != "stdin" {
		t.Errorf("Parent = %q", got.Parent)
	}
}

func TestDeriveContainer_Unknown(t *testing.T) {
	c := &sources.Chunk{
		SourceName:     "custom-source",
		SourceMetadata: sources.Metadata{},
	}
	got := DeriveContainer(c)
	if got.Container != "custom-source" {
		t.Errorf("Container = %q", got.Container)
	}
	if got.Parent != "" {
		t.Errorf("Parent = %q, want empty", got.Parent)
	}
}

func TestDeriveContainer_Nil(t *testing.T) {
	got := DeriveContainer(nil)
	if got.Container != "" || got.Parent != "" || got.Extension != "" {
		t.Errorf("nil chunk should return zero ContainerKey, got %+v", got)
	}
}
