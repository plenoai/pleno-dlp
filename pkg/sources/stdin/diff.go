package stdin

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// hunkNewStartRe extracts the new-side start line from "@@ -a,b +c,d @@".
var hunkNewStartRe = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// ParseDiff reduces a unified diff to the text a change adds:
//
//   - "+" lines inside a hunk are kept with the leading "+" removed, so
//     detectors anchored on line starts or "KEY=value" see real content.
//   - "-" lines are dropped: scanning a secret being deleted would block
//     the very commit that removes it. Context (" ") lines are dropped
//     because they are already committed and were gated earlier.
//   - "+++ b/<path>" headers are kept verbatim so the buffer stays
//     attributable when read by hand; other headers ("diff --git",
//     "index", "---", "@@") are dropped.
//
// Hunk state matters: inside a hunk, "+++x" is an added line "++x", not
// a header. The returned locations are indexed by buffer line (0-based)
// and give the file and new-side line each buffer line came from; Line is
// 0 for a "+++" header. A diff with no added lines returns nil, nil.
func ParseDiff(diff []byte) ([]byte, []sources.LineLocation) {
	var out bytes.Buffer
	var locs []sources.LineLocation
	path, newLine, inHunk := "", 0, false
	emit := func(text string, loc sources.LineLocation) {
		out.WriteString(text)
		out.WriteByte('\n')
		locs = append(locs, loc)
	}
	for _, line := range strings.Split(string(diff), "\n") {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			inHunk = false
		case strings.HasPrefix(line, "@@"):
			if m := hunkNewStartRe.FindStringSubmatch(line); m != nil {
				newLine, _ = strconv.Atoi(m[1])
				inHunk = true
			}
		case inHunk && strings.HasPrefix(line, "+"):
			emit(line[1:], sources.LineLocation{Path: path, Line: newLine})
			newLine++
		case inHunk && strings.HasPrefix(line, " "):
			newLine++
		case inHunk:
			// "-" removals and "\ No newline at end of file" add nothing.
		case strings.HasPrefix(line, "+++ "):
			path = diffFilePath(strings.TrimPrefix(line, "+++ "))
			emit(line, sources.LineLocation{Path: path})
		}
	}
	for _, l := range locs {
		if l.Line > 0 {
			return out.Bytes(), locs
		}
	}
	return nil, nil
}

// LocationMap converts ParseDiff's per-buffer-line slice into the 1-based
// map StdinMeta.Locations expects, skipping lines with no known path.
func LocationMap(locs []sources.LineLocation) map[int]sources.LineLocation {
	if len(locs) == 0 {
		return nil
	}
	m := make(map[int]sources.LineLocation, len(locs))
	for i, l := range locs {
		if l.Path != "" {
			m[i+1] = l
		}
	}
	return m
}

// diffFilePath extracts the new-side path from a "+++ " header value. Git
// prefixes paths with "b/", quotes them when they contain special bytes,
// may append a tab-separated timestamp, and uses /dev/null for deletions.
func diffFilePath(header string) string {
	path := strings.TrimRight(header, "\r")
	if !strings.HasPrefix(path, `"`) {
		if i := strings.IndexByte(path, '\t'); i >= 0 {
			path = path[:i]
		}
	} else if unquoted, err := strconv.Unquote(path); err == nil {
		path = unquoted
	}
	if path == "/dev/null" {
		return ""
	}
	return strings.TrimPrefix(path, "b/")
}
