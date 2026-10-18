package stdin

import (
	"strconv"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// CollectDiffForScan parses a unified diff and returns the added lines,
// leading '+' stripped and concatenated in file/hunk order, together with a
// map from the 1-based line number of each added line in the returned
// content to the source file path and 1-based line it came from.
//
// protect and the cursor agent hook scan only the added lines of a diff.
// Feeding the concatenated bytes through the stdin source used to erase the
// file each line came from, so allowlist `path` entries never matched and
// the output location column showed an opaque label. The returned map lets
// callers thread the real provenance back into the result metadata.
func CollectDiffForScan(diff []byte) ([]byte, map[int]sources.LineLocation) {
	var sb strings.Builder
	locations := make(map[int]sources.LineLocation)
	lineNo := 0
	path := ""
	newLine := 0
	inHunk := false
	for _, line := range strings.SplitAfter(string(diff), "\n") {
		switch {
		case strings.HasPrefix(line, "+++ "):
			path = diffFilePath(line[4:])
			inHunk = false
		case strings.HasPrefix(line, "@@ "):
			start, ok := hunkNewStart(line)
			newLine, inHunk = start, ok
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			sb.WriteString(line[1:])
			lineNo++
			resolved := newLine
			if !inHunk {
				// A '+' line outside a hunk has no known new-side line;
				// keep the path so allowlist matching still works.
				resolved = 0
			}
			locations[lineNo] = sources.LineLocation{Path: path, Line: resolved}
			newLine++
		default:
			if !inHunk {
				continue
			}
			switch {
			case strings.HasPrefix(line, " "):
				newLine++
			case strings.HasPrefix(line, "-"):
				// Removed old-side line; the new-side counter is unchanged.
			}
		}
	}
	return []byte(sb.String()), locations
}

// diffFilePath extracts the new-side path from a "+++ " diff header. Git
// prefixes paths with "b/", quotes them when they contain special bytes, and
// uses /dev/null for deletions.
func diffFilePath(header string) string {
	path := strings.TrimRight(header, "\r\n")
	if i := strings.IndexByte(path, '\t'); i >= 0 {
		path = path[:i]
	}
	path = strings.TrimSpace(path)
	if unquoted, err := strconv.Unquote(path); err == nil {
		path = unquoted
	}
	path = strings.TrimPrefix(path, "b/")
	if path == "/dev/null" {
		return ""
	}
	return path
}

// hunkNewStart returns the new-side start line from a "@@ -a,b +c,d @@" hunk
// header. ok is false when the header carries no parseable new-side start.
func hunkNewStart(header string) (int, bool) {
	plus := strings.IndexByte(header, '+')
	if plus < 0 {
		return 0, false
	}
	start := plus + 1
	end := start
	for end < len(header) && header[end] >= '0' && header[end] <= '9' {
		end++
	}
	if end == start {
		return 0, false
	}
	n, err := strconv.Atoi(header[start:end])
	return n, err == nil
}
