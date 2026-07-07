package output

import (
	"fmt"
	"io"
	"strconv"
	"sync"
	"text/tabwriter"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
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
		fmt.Fprintln(s.tw, "DETECTOR\tVERDICT\tLOCATION\tREDACTED\tSUPPRESSED")
		s.headered = true
	}
	// SUPPRESSED is blank for every ordinary row; it's populated only
	// under --show-suppressed, where a suppression sink's audit fan-out
	// forwards a finding here with SuppressedBy set instead of dropping
	// it — see engine.Finding.SuppressedBy (issue #290). Additive
	// column: existing table-format consumers that grep/awk fixed
	// column positions still find DETECTOR..REDACTED unchanged.
	fmt.Fprintf(s.tw, "%s\t%s\t%s\t%s\t%s\n",
		f.Detector.String(),
		verdictSymbol(f),
		tableLocationOf(f),
		f.Result.Redacted,
		f.SuppressedBy,
	)
}

func (s *tableSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tw.Flush()
}

// verdictSymbol renders the three-valued verification verdict. Collapsing
// "provider confirmed dead" and "verification attempt failed" into the same
// cross symbol is exactly what let --only-verified silently drop possibly-
// live secrets during an outage (#246) — "?" keeps that case visually
// distinct from a confirmed-dead credential.
func verdictSymbol(f engine.Finding) string {
	switch f.Result.Verdict() {
	case detectors.VerdictVerified:
		return "✓"
	case detectors.VerdictIndeterminate:
		return "?"
	default:
		return "✗"
	}
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
