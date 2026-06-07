// Package piidb implements cross-finding PIIDB candidate detection and
// severity escalation. It analyses PII findings post-scan, groups them
// by logical container and parent, then escalates severity when findings
// form structured or dense clusters indicative of personal-data datasets.
package piidb

import (
	"path"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// ContainerKey identifies a logical container (file, object, document,
// message) that groups PII findings. Parent identifies the container's
// logical parent (directory, prefix, space, channel). Extension carries
// the file-format hint when available.
type ContainerKey struct {
	Container string
	Parent    string
	Extension string
}

// DeriveContainer extracts a source-agnostic container key from chunk
// metadata. Every source type is covered; unknown sources degrade to
// the SourceName fallback so PIIDB density analysis still functions
// (at least same-container clustering) even for future sources that
// haven't received explicit support.
func DeriveContainer(c *sources.Chunk) ContainerKey {
	if c == nil {
		return ContainerKey{}
	}
	md := c.SourceMetadata
	switch {
	case md.Filesystem != nil:
		p := md.Filesystem.Path
		return ContainerKey{
			Container: p,
			Parent:    path.Dir(p),
			Extension: extOf(p),
		}
	case md.Git != nil:
		g := md.Git
		container := g.Repository + "@" + g.Commit + ":" + g.File
		return ContainerKey{
			Container: container,
			Parent:    g.Repository + ":" + path.Dir(g.File),
			Extension: extOf(g.File),
		}
	case md.GitHub != nil:
		gh := md.GitHub
		container := gh.Repository + "@" + gh.Commit + ":" + gh.File
		return ContainerKey{
			Container: container,
			Parent:    gh.Repository + ":" + path.Dir(gh.File),
			Extension: extOf(gh.File),
		}
	case md.GitLab != nil:
		gl := md.GitLab
		container := gl.Group + "/" + gl.Project + "@" + gl.Sha + ":" + gl.Path
		return ContainerKey{
			Container: container,
			Parent:    gl.Group + "/" + gl.Project + ":" + path.Dir(gl.Path),
			Extension: extOf(gl.Path),
		}
	case md.S3 != nil:
		s := md.S3
		container := "s3://" + s.Bucket + "/" + s.Key
		parent := "s3://" + s.Bucket + "/" + s3Parent(s.Key)
		return ContainerKey{
			Container: container,
			Parent:    parent,
			Extension: extOf(s.Key),
		}
	case md.GCS != nil:
		g := md.GCS
		container := "gs://" + g.Bucket + "/" + g.Object
		parent := "gs://" + g.Bucket + "/" + s3Parent(g.Object)
		return ContainerKey{
			Container: container,
			Parent:    parent,
			Extension: extOf(g.Object),
		}
	case md.Slack != nil:
		s := md.Slack
		return ContainerKey{
			Container: s.Channel + "@" + s.Timestamp,
			Parent:    s.Channel,
			Extension: "",
		}
	case md.Confluence != nil:
		cf := md.Confluence
		return ContainerKey{
			Container: cf.SpaceKey + "/" + cf.PageID,
			Parent:    cf.SpaceKey,
			Extension: "",
		}
	case md.Jira != nil:
		j := md.Jira
		return ContainerKey{
			Container: j.Project + "/" + j.IssueKey + ":" + j.Part,
			Parent:    j.Project,
			Extension: "",
		}
	case md.Notion != nil:
		n := md.Notion
		container := n.PageID + ":" + n.Part
		parent := n.Database
		if parent == "" {
			parent = n.PageID
		}
		return ContainerKey{
			Container: container,
			Parent:    parent,
			Extension: "",
		}
	case md.Bitbucket != nil:
		bb := md.Bitbucket
		container := bb.Workspace + "/" + bb.Repo + "@" + bb.Commit + ":" + bb.Path
		return ContainerKey{
			Container: container,
			Parent:    bb.Workspace + "/" + bb.Repo + ":" + path.Dir(bb.Path),
			Extension: extOf(bb.Path),
		}
	case md.Forge != nil:
		f := md.Forge
		container := f.Provider + "/" + f.Repository + "@" + f.Commit + ":" + f.File
		return ContainerKey{
			Container: container,
			Parent:    f.Provider + "/" + f.Repository + ":" + path.Dir(f.File),
			Extension: extOf(f.File),
		}
	case md.Stdin != nil:
		return ContainerKey{
			Container: "stdin:" + md.Stdin.Label,
			Parent:    "stdin",
			Extension: "",
		}
	default:
		return ContainerKey{
			Container: c.SourceName,
			Parent:    "",
			Extension: "",
		}
	}
}

func extOf(p string) string {
	ext := path.Ext(p)
	if ext != "" {
		return strings.ToLower(ext[1:])
	}
	return ""
}

func s3Parent(key string) string {
	if i := strings.LastIndex(key, "/"); i >= 0 {
		return key[:i]
	}
	return ""
}
