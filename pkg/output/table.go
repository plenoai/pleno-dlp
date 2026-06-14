package output

import (
	"fmt"
	"io"
	"strconv"
	"sync"
	"text/tabwriter"

	"github.com/plenoai/pleno-dlp/pkg/engine"
)

// tableSink renders findings as a column-aligned ASCII table. The header is
// emitted lazily on the first Emit so a zero-finding scan prints nothing —
// callers that want explicit "no findings" wording can layer that themselves.
type tableSink struct {
	mu       sync.Mutex
	tw       *tabwriter.Writer
	headered bool
}

func newTableSink(w io.Writer) *tableSink {
	return &tableSink{
		tw: tabwriter.NewWriter(w, 0, 0, 2, ' ', 0),
	}
}

func (s *tableSink) Emit(f engine.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.headered {
		fmt.Fprintln(s.tw, "DETECTOR\tVERIFIED\tLOCATION\tREDACTED")
		s.headered = true
	}
	fmt.Fprintf(s.tw, "%s\t%s\t%s\t%s\n",
		f.Detector.String(),
		verifiedSymbol(f),
		tableLocationOf(f),
		f.Result.Redacted,
	)
}

func (s *tableSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tw.Flush()
}

// verifiedSymbol renders the verification result: verification is
// unconditional (verify-by-default since #165), so every finding has a
// definite answer — check when the provider confirmed the secret is live,
// cross otherwise.
func verifiedSymbol(f engine.Finding) string {
	if f.Result.Verified {
		return "✓"
	}
	return "✗"
}

func tableLocationOf(f engine.Finding) string {
	if f.Chunk == nil {
		return ""
	}
	md := f.Chunk.SourceMetadata
	switch {
	case md.Filesystem != nil:
		return md.Filesystem.Path + ":" + strconv.Itoa(md.Filesystem.Line)
	case md.Git != nil:
		return md.Git.Repository + "@" + md.Git.Commit + ":" + md.Git.File + ":" + strconv.Itoa(md.Git.Line)
	case md.GitHub != nil:
		return md.GitHub.Repository + "@" + md.GitHub.Commit + ":" + md.GitHub.File + ":" + strconv.Itoa(md.GitHub.Line)
	case md.S3 != nil:
		return "s3://" + md.S3.Bucket + "/" + md.S3.Key
	case md.GCS != nil:
		return "gs://" + md.GCS.Bucket + "/" + md.GCS.Object
	case md.Slack != nil:
		return md.Slack.Channel + "@" + md.Slack.Timestamp
	case md.Stdin != nil:
		return md.Stdin.Label
	case md.Forge != nil:
		return md.Forge.Repository + "@" + md.Forge.Commit + ":" + md.Forge.File + ":" + strconv.Itoa(md.Forge.Line)
	case md.SIEM != nil:
		return md.SIEM.Provider + "://" + md.SIEM.Host + "/" + md.SIEM.Index + "@" + md.SIEM.EventID
	case md.SQLDump != nil:
		loc := md.SQLDump.File + ":" + strconv.Itoa(md.SQLDump.Line)
		if md.SQLDump.Table != "" {
			loc += " [" + md.SQLDump.Table + "]"
		}
		return loc
	}
	return f.Chunk.SourceType.String()
}
